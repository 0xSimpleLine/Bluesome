//types

#[derive(Debug, PartialEq, Clone)]
pub struct Param {
    pub id: String,
    pub ad: String,
    pub salt1: String,
    pub salt2: String
}

#[derive(Debug, PartialEq, Clone)]
pub struct Secret {
    pub id: String,
    pub message: String
}
