#[macro_use]
extern crate rocket;

use std::path::Path;
use std::str::from_utf8;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs};

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use regex::Regex;
use rocket::data::{Capped, Limits, ToByteUnit};
use rocket::fairing::AdHoc;
use rocket::fs::{FileServer, TempFile};
use rocket::http::Status;
use rocket::outcome::try_outcome;
use rocket::request::{FromRequest, Outcome};
use rocket::response::status;
use rocket::serde::json::Json;
use rocket::{Config, Request, State};
use serde::{Deserialize, Serialize};
use sled::{Db, Tree};

#[derive(Serialize)]
struct FileUploadResponse {
    id: String,
    url: String,
    preview_url: String,
    deletion_token: String,
}

#[derive(Serialize)]
struct UserTokenResponse {
    token: String,
}

#[derive(Serialize)]
struct FileResponse {
    name: String,
    username: String,
    original_name: String,
    size: u64,
    created_at: usize,
}

#[derive(Serialize)]
struct GenericResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct CreateUserData {
    username: String,
    admin: bool,
}

#[derive(Serialize)]
struct FullUserData {
    username: String,
    #[serde(flatten)]
    user_data: UserData,
}

#[derive(Serialize)]
struct FullFileData {
    filename: String,
    #[serde(flatten)]
    file_data: FileData,
}

#[derive(Serialize)]
struct FullAuthTokenData {
    username: String,
    #[serde(flatten)]
    token_data: AuthTokenData,
}

#[derive(Deserialize, Serialize)]
struct AuthTokenData {
    id: String,
    issued_at: usize,
    issued_by: String,
}

#[derive(Deserialize, Serialize)]
struct FileData {
    username: String,
    original_name: String,
    // size in bytes
    size: u64,
    created_at: usize,
}

#[derive(Deserialize, Serialize)]
struct UserData {
    admin: bool,
}

struct Database {
    users: Tree,
    tokens: Tree,
    public: Tree,
    root: Db,
}

struct GlobalData {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

#[derive(Debug, Serialize, Deserialize)]
struct UserTokenClaims {
    // Username
    aud: String,
    // Issued at (as UTC timestamp)
    iat: usize,
    // Issuer
    iss: String,
    // Token ID
    sub: String,
    // Admin
    admin: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct DeletionTokenClaims {
    // File ID
    aud: String,
    // Issued at (as UTC timestamp)
    iat: usize,
    // Issuer
    iss: String,
}

macro_rules! get_env {
    ($a: tt) => {{
        env::var($a).expect(concat!($a, " is not set"))
    }};
}

static GLOBAL_DATA: Lazy<GlobalData> = Lazy::new(|| GlobalData {
    encoding_key: EncodingKey::from_secret(get_env!("SECRET_KEY").as_ref()),
    decoding_key: DecodingKey::from_secret(get_env!("SECRET_KEY").as_ref()),
});

static DATA_DIR: Lazy<String> = Lazy::new(|| get_env!("DATA_DIR"));
static BASEURL: Lazy<String> = Lazy::new(|| get_env!("BASEURL"));

#[rocket::async_trait]
impl<'r> FromRequest<'r> for UserTokenClaims {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<UserTokenClaims, ()> {
        let token = req.headers().get_one("Authorization");
        match token {
            Some(token) => {
                let mut validation = Validation::new(Algorithm::default());
                validation.validate_exp = false;
                validation.required_spec_claims.remove("exp");

                let decoding_key = (*GLOBAL_DATA).decoding_key.clone();

                let token = match decode::<UserTokenClaims>(&token, &decoding_key, &validation) {
                    Ok(t) => t,
                    Err(_err) => {
                        return Outcome::Failure((Status::Unauthorized, ()));
                    }
                };

                Outcome::Success(token.claims)
            }
            None => Outcome::Failure((Status::BadRequest, ())),
        }
    }
}

struct User {
    user: UserData,
    token: UserTokenClaims,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for User {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<User, ()> {
        let token = try_outcome!(request.guard::<UserTokenClaims>().await);

        let db = request
            .guard::<&State<Database>>()
            .await
            .succeeded()
            .unwrap();

        if &token.aud == "system" {
            return if db.users.len() == 0 {
                Outcome::Success(User {
                    user: UserData { admin: true },
                    token,
                })
            } else {
                Outcome::Failure((Status::Unauthorized, ()))
            };
        }

        match db.tokens.get(&token.aud).unwrap() {
            Some(bytes) => {
                let token_data: AuthTokenData = bincode::deserialize(&bytes).unwrap();
                if token_data.id != token.sub {
                    return Outcome::Failure((Status::Unauthorized, ()));
                }
            }
            None => {
                return Outcome::Failure((Status::Unauthorized, ()));
            }
        };

        let user_data = match db.users.get(&token.aud).unwrap() {
            Some(bytes) => {
                let user_data: UserData = bincode::deserialize(&bytes).unwrap();
                user_data
            }
            None => {
                return Outcome::Failure((Status::Unauthorized, ()));
            }
        };

        Outcome::Success(User {
            user: user_data,
            token,
        })
    }
}

struct Admin {
    user: Option<UserData>,
    token: UserTokenClaims,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Admin {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Admin, ()> {
        let user = try_outcome!(request.guard::<User>().await);
        if !user.user.admin {
            return Outcome::Failure((Status::Unauthorized, ()));
        }
        return if &user.token.aud == "system" {
            Outcome::Success(Admin {
                user: None,
                token: user.token,
            })
        } else {
            Outcome::Success(Admin {
                user: Option::from(user.user),
                token: user.token,
            })
        };
    }
}

fn verify_username(username: String) -> bool {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new("^[a-z\\d_]+$").unwrap());

    RE.is_match(&*username) && !["system", "self"].contains(&&*username)
}

fn format_filename(name: String) -> String {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new("[^\\dA-Za-z_\\-.]+").unwrap());
    RE.replace_all(&*name, "_").to_string()
}

fn generate_filename(name: String) -> String {
    format!(
        "{}_{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("how on earth is your system time before the epoch")
            .as_secs(),
        format_filename(name)
    )
}

#[get("/")]
fn index() -> &'static str {
    "usage.txt should help you if you're lost"
}

#[get("/usage.txt")]
fn usage() -> &'static str {
    "USAGE:

Authentication: `Authorization` header with user or admin token

[n] - No authentication
[a] - Admin authentication
[u] - User authentication

If a request takes JSON you will need a
`Content-Type: application/json` header

GET /usage.txt [n]
    This message

GET /api/files [n]
    Get a list of all files

GET /api/files/[name] [n]
    Get a specific file's metadata

DELETE /api/files/[name] [u]
    Delete the file if you are the file's owner, or an admin

POST /api/files/?name=[filename] [u]
    Upload a file, send file as binary data
    Responds with file URL

GET /api/users [a]
    Get all users

GET /api/user/[username] [a]
    Get specific user

POST /api/users [a]
    Create a new user
    {
        \"username\": \"[username]\",
        \"admin\": false
    }
    Responds with the new user's token

PUT /api/users/[username] [a]
    Update a user
    {
        \"admin\": false
    }

GET /api/tokens [a]
    Get metadata for all user tokens - one token per user

PUT /api/tokens/self [u]
    Regenerate your own token

PUT /api/tokens/[user] [a]
    Regenerate a user's token

There is no option to delete a user, but regenerating their
token will make them loose any access

GET /[file] [n]
    Sends file"
}

// amding stunf
#[get("/users/<username>")]
fn get_user(
    db: &State<Database>,
    username: String,
    _admin: Admin,
) -> Result<Json<GenericResponse<UserData>>, status::Custom<Json<GenericResponse<UserData>>>> {
    return match db.users.get(&username).unwrap() {
        Some(bytes) => {
            let user_data: UserData = bincode::deserialize(&bytes).unwrap();
            Ok(Json(GenericResponse {
                success: true,
                data: Option::from(user_data),
                error: None,
            }))
        }
        None => Err(status::Custom(
            Status::NotFound,
            Json(GenericResponse {
                success: false,
                data: None,
                error: Option::from("User not found".to_string()),
            }),
        )),
    };
}

#[get("/users")]
fn get_users(db: &State<Database>, _admin: Admin) -> Json<GenericResponse<Vec<FullUserData>>> {
    let mut res = Vec::new();
    for kv in db.users.iter() {
        let d = kv.unwrap();
        let user_data: UserData = bincode::deserialize(&d.1).unwrap();

        let username = match from_utf8(&*d.0) {
            Ok(v) => v.to_string(),
            Err(e) => panic!("invalid UTF-8 sequence: {}", e),
        };

        let user = FullUserData {
            username,
            user_data,
        };

        res.push(user);
    }
    Json(GenericResponse {
        success: true,
        data: Option::from(res),
        error: None,
    })
}

#[post("/users", data = "<user>")]
fn create_user(
    db: &State<Database>,
    user: Json<CreateUserData>,
    admin: Admin,
) -> Result<
    Json<GenericResponse<UserTokenResponse>>,
    status::Custom<Json<GenericResponse<UserTokenResponse>>>,
> {
    if !verify_username((user.0.username).clone()) {
        return Err(status::Custom(Status::BadRequest, Json(GenericResponse {
            success: false,
            data: None,
            error: Option::from(String::from(
                "Invalid username, must match ^[a-z\\d_]+$ and cannot be \"system\" or \"self\"",
            )),
        })));
    }

    if db.users.contains_key(&user.0.username).unwrap() {
        return Err(status::Custom(
            Status::Conflict,
            Json(GenericResponse {
                success: false,
                data: None,
                error: Option::from(String::from(
                    "User already exists, please use PUT to update",
                )),
            }),
        ));
    }

    match db.users.insert(
        &user.0.username,
        bincode::serialize(&UserData {
            admin: user.0.admin,
        })
        .unwrap(),
    ) {
        Ok(_) => {}
        Err(err) => {
            panic!("{}", err)
        }
    }

    let token_id: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect();

    let token_claims = UserTokenClaims {
        aud: user.0.username.to_string(),
        iat: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("how on earth is your system time before the epoch")
            .as_secs() as usize,
        iss: admin.token.aud,
        sub: token_id.to_string(),
        admin: user.0.admin,
    };

    match db.tokens.insert(
        user.0.username.to_string(),
        bincode::serialize(&AuthTokenData {
            id: token_id.to_string(),
            issued_at: token_claims.iat,
            issued_by: token_claims.iss.to_string(),
        })
        .unwrap(),
    ) {
        Ok(_) => {}
        Err(err) => {
            panic!("{}", err)
        }
    }

    let token = encode(
        &Header::default(),
        &token_claims,
        &(*GLOBAL_DATA).encoding_key,
    )
    .expect("error creating JWT");

    Ok(Json(GenericResponse {
        success: true,
        data: Option::from(UserTokenResponse { token }),
        error: None,
    }))
}

#[put("/users/<username>", data = "<data>")]
fn update_user(
    username: String,
    db: &State<Database>,
    _admin: Admin,
    data: Json<UserData>,
) -> Result<Json<GenericResponse<UserData>>, status::Custom<Json<GenericResponse<UserData>>>> {
    match db.users.get(&username).unwrap() {
        Some(_) => {}
        None => {
            return Err(status::Custom(
                Status::NotFound,
                Json(GenericResponse {
                    success: false,
                    data: None,
                    error: Option::from("User not found".to_string()),
                }),
            ));
        }
    };

    match db
        .users
        .insert(&username, bincode::serialize(&data.0).unwrap())
    {
        Ok(_) => {}
        Err(err) => {
            panic!("{}", err)
        }
    }

    Ok(Json(GenericResponse {
        success: true,
        data: Option::from(data.0),
        error: None,
    }))
}

#[get("/tokens")]
fn get_tokens(
    db: &State<Database>,
    _admin: Admin,
) -> Json<GenericResponse<Vec<FullAuthTokenData>>> {
    let mut res = Vec::new();
    for kv in db.tokens.iter() {
        let d = kv.unwrap();
        let token_data: AuthTokenData = bincode::deserialize(&d.1).unwrap();

        let username = match from_utf8(&*d.0) {
            Ok(v) => v.to_string(),
            Err(e) => panic!("invalid UTF-8 sequence: {}", e),
        };

        res.push(FullAuthTokenData {
            username,
            token_data,
        });
    }
    Json(GenericResponse {
        success: true,
        data: Option::from(res),
        error: None,
    })
}

#[put("/tokens/self")]
fn regenerate_self_token(
    db: &State<Database>,
    user: User,
) -> Json<GenericResponse<UserTokenResponse>> {
    let token_id: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect();

    let token_claims = UserTokenClaims {
        aud: user.token.aud.to_string(),
        iat: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("how on earth is your system time before the epoch")
            .as_secs() as usize,
        iss: user.token.aud.to_string(),
        sub: token_id.to_string(),
        admin: user.user.admin,
    };

    match db.tokens.insert(
        user.token.aud.to_string(),
        bincode::serialize(&AuthTokenData {
            id: token_id.to_string(),
            issued_at: token_claims.iat,
            issued_by: token_claims.iss.to_string(),
        })
        .unwrap(),
    ) {
        Ok(_) => {}
        Err(err) => {
            panic!("{}", err)
        }
    }

    Json(GenericResponse {
        success: true,
        data: Option::from(UserTokenResponse {
            token: encode(
                &Header::default(),
                &token_claims,
                &(*GLOBAL_DATA).encoding_key,
            )
            .expect("error creating JWT"),
        }),
        error: None,
    })
}

#[put("/tokens/<username>")]
fn regenerate_user_token(
    db: &State<Database>,
    _admin: Admin,
    username: String,
) -> Result<
    Json<GenericResponse<UserTokenResponse>>,
    status::Custom<Json<GenericResponse<UserTokenResponse>>>,
> {
    let user: UserData = match db.users.get(&username).unwrap() {
        Some(bytes) => bincode::deserialize(&bytes).unwrap(),
        None => {
            return Err(status::Custom(
                Status::NotFound,
                Json(GenericResponse {
                    success: false,
                    data: None,
                    error: Option::from("User not found".to_string()),
                }),
            ));
        }
    };

    let token_id: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect();

    let token_claims = UserTokenClaims {
        aud: username.to_string(),
        iat: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("how on earth is your system time before the epoch")
            .as_secs() as usize,
        iss: username.to_string(),
        sub: token_id.to_string(),
        admin: user.admin,
    };

    match db.tokens.insert(
        username.to_string(),
        bincode::serialize(&AuthTokenData {
            id: token_id.to_string(),
            issued_at: token_claims.iat,
            issued_by: token_claims.iss.to_string(),
        })
        .unwrap(),
    ) {
        Ok(_) => {}
        Err(err) => {
            panic!("{}", err)
        }
    }

    Ok(Json(GenericResponse {
        success: true,
        data: Option::from(UserTokenResponse {
            token: encode(
                &Header::default(),
                &token_claims,
                &(*GLOBAL_DATA).encoding_key,
            )
            .expect("error creating JWT"),
        }),
        error: None,
    }))
}

// teiny imgea upoloqder :+1
#[get("/files/<name>")]
fn get_file(
    name: String,
    db: &State<Database>,
) -> Result<Json<GenericResponse<FileData>>, status::Custom<Json<GenericResponse<FileData>>>> {
    return match db.public.get(&name).unwrap() {
        Some(bytes) => {
            let file_data: FileData = bincode::deserialize(&bytes).unwrap();
            Ok(Json(GenericResponse {
                success: true,
                data: Option::from(file_data),
                error: None,
            }))
        }
        None => Err(status::Custom(
            Status::NotFound,
            Json(GenericResponse {
                success: false,
                data: None,
                error: Option::from("File not found".to_string()),
            }),
        )),
    };
}

#[delete("/files/<raw_name>")]
fn delete_file(
    raw_name: String,
    db: &State<Database>,
    user: User,
) -> Result<
    Json<GenericResponse<Option<String>>>,
    status::Custom<Json<GenericResponse<Option<String>>>>,
> {
    let name = format_filename(raw_name);

    if !user.token.admin {
        match db.public.get(&name).unwrap() {
            Some(bytes) => {
                let file_data: FileData = bincode::deserialize(&bytes).unwrap();
                if file_data.username != user.token.aud {
                    return Err(status::Custom(
                        Status::Unauthorized,
                        Json(GenericResponse {
                            success: false,
                            data: None,
                            error: Option::from("You do not have access to this file".to_string()),
                        }),
                    ));
                }
            }
            None => {
                return Err(status::Custom(
                    Status::NotFound,
                    Json(GenericResponse {
                        success: false,
                        data: None,
                        error: Option::from("File not found".to_string()),
                    }),
                ));
            }
        };
    }

    fs::remove_file(Path::new(&*DATA_DIR).join("files/").join(&name)).unwrap();

    db.public.remove(&name).unwrap();

    Ok(Json(GenericResponse {
        success: true,
        data: None,
        error: None,
    }))
}

#[get("/files")]
fn all_files(db: &State<Database>) -> Json<GenericResponse<Vec<FullFileData>>> {
    let mut res = Vec::new();
    for kv in db.public.iter() {
        let d = kv.unwrap();
        let file_data: FileData = bincode::deserialize(&d.1).unwrap();

        let filename = match from_utf8(&*d.0) {
            Ok(v) => v.to_string(),
            Err(e) => panic!("invalid UTF-8 sequence: {}", e),
        };

        let file = FullFileData {
            filename,
            file_data,
        };

        res.push(file);
    }
    Json(GenericResponse {
        success: true,
        data: Option::from(res),
        error: None,
    })
}

#[post("/files?<name>", data = "<file>")]
async fn upload_file(
    db: &State<Database>,
    mut file: Capped<TempFile<'_>>,
    name: String,
    user: User,
) -> Result<Json<GenericResponse<String>>, status::Custom<Json<GenericResponse<String>>>> {
    let id = generate_filename(name.to_string());

    if file.is_complete() && !file.is_empty() {
        file.move_copy_to(Path::new(&*DATA_DIR).join("files/").join(&id))
            .await
            .unwrap();
    } else {
        return Err(status::Custom(
            Status::UnprocessableEntity,
            Json(GenericResponse {
                success: false,
                data: None,
                error: Option::from("Bad file :(".to_string()),
            }),
        ));
    }

    match db.public.insert(
        &id,
        bincode::serialize(&FileData {
            username: user.token.aud,
            original_name: name.to_string(),
            size: file.len(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("how on earth is your system time before the epoch")
                .as_secs() as usize,
        })
        .unwrap(),
    ) {
        Ok(_) => {}
        Err(err) => {
            panic!("{}", err)
        }
    }

    Ok(Json(GenericResponse {
        success: true,
        data: Option::from(format!("{host}/{id}", host = *BASEURL, id = id)),
        error: None,
    }))
}

#[catch(400)]
fn api_bad_request(_req: &Request) -> Json<GenericResponse<String>> {
    Json(GenericResponse {
        success: false,
        data: None,
        error: Option::from(
            "The request could not be understood by the server due to malformed syntax."
                .to_string(),
        ),
    })
}

#[catch(401)]
fn api_unauthorized(_req: &Request) -> Json<GenericResponse<String>> {
    Json(GenericResponse {
        success: false,
        data: None,
        error: Option::from("The request requires user authentication.".to_string()),
    })
}

#[catch(404)]
fn api_not_found(_req: &Request) -> Json<GenericResponse<String>> {
    Json(GenericResponse {
        success: false,
        data: None,
        error: Option::from("The requested resource could not be found.".to_string()),
    })
}

#[catch(422)]
fn api_unprocessable_entity(_req: &Request) -> Json<GenericResponse<String>> {
    Json(GenericResponse {
        success: false,
        data: None,
        error: Option::from(
            "The request was well-formed but was unable to be followed due to semantic errors."
                .to_string(),
        ),
    })
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    match fs::create_dir_all(Path::new(&*DATA_DIR).join("db")) {
        Err(e) => panic!("{}", e),
        _ => {}
    }
    match fs::create_dir_all(Path::new(&*DATA_DIR).join("files")) {
        Err(e) => panic!("{}", e),
        _ => {}
    }

    let db = sled::open(Path::new(&*DATA_DIR).join("db/")).expect("failed to open database");

    if db.open_tree(&[0]).expect("failed to users tree").len() == 0 {
        let token = encode(
            &Header::default(),
            &UserTokenClaims {
                aud: "system".to_string(),
                iat: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("how on earth is your system time before the epoch")
                    .as_secs() as usize,
                iss: "system".to_string(),
                sub: 0.to_string(),
                admin: true,
            },
            &(*GLOBAL_DATA).encoding_key,
        )
        .expect("error creating system JWT");
        println!(
            "This is your system token, it was created because your database has no users \
        and it will only work while you have none.\n{}",
            token
        );
    }

    let figment = Config::figment()
        .merge(("limits", Limits::new().limit("file", 256.mebibytes())))
        .merge(("address", get_env!("ADDRESS")));

    rocket::custom(figment)
        .manage(Database {
            users: db.open_tree(&[0]).expect("failed to open users tree"),
            tokens: db.open_tree(&[1]).expect("failed to open tokens tree"),
            public: db.open_tree(&[2]).expect("failed to public tree"),
            root: db,
        })
        .attach(AdHoc::on_response("Server header", |_, res| {
            Box::pin(async move {
                res.set_header(rocket::http::Header::new("Server", "rs-imagehost"));
            })
        }))
        .mount("/", routes![index, usage])
        .mount(
            "/api/",
            routes![
                get_file,
                all_files,
                upload_file,
                get_users,
                get_user,
                create_user,
                update_user,
                delete_file,
                get_tokens,
                regenerate_self_token,
                regenerate_user_token,
            ],
        )
        .register(
            "/api/",
            catchers![
                api_not_found,
                api_bad_request,
                api_unprocessable_entity,
                api_unauthorized
            ],
        )
        .mount("/", FileServer::from(Path::new(&*DATA_DIR).join("files")))
        .launch()
        .await
}
