fn main() {
    let _profile = Json(MProfile {
        avatar_url: "mxc://modlin.dev/id_xxx".to_string(),
        displayname: "Sumaiya Chowdhury".to_string(),
        m_tz: "Asia/Dhaka".to_string(),
    });
    let _forbidden = (
        StatusCode::FORBIDDEN,
        Json(MatrixError {
            errcode: ErrCode::MForbidden,
            error: Some("Profile lookup is disabled on this homeserver".to_string()),
        }),
    );
}
