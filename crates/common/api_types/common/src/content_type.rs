use actix_web::http::header::HeaderValue as ActixHeaderValue;
use reqwest::header::HeaderValue as ReqwestHeaderValue;

pub const JSON_ACCEPT_PRIORITY: &str = "application/json;q=1";
pub const JSON_CONTENT_TYPE: &str = "application/json";
pub const SSZ_CONTENT_TYPE: &str = "application/octet-stream";

#[derive(Debug, Clone)]
pub enum ContentType {
    Json,
    Ssz,
}

impl ContentType {
    pub fn to_header_value(&self) -> ReqwestHeaderValue {
        match self {
            ContentType::Json => ReqwestHeaderValue::from_static(JSON_CONTENT_TYPE),
            ContentType::Ssz => ReqwestHeaderValue::from_static(SSZ_CONTENT_TYPE),
        }
    }
}

impl From<Option<&ActixHeaderValue>> for ContentType {
    fn from(header_value: Option<&ActixHeaderValue>) -> Self {
        let Some(value) = header_value.and_then(|h| h.to_str().ok()) else {
            return ContentType::Json;
        };
        let mut json_quality = 0.0_f32;
        let mut ssz_quality = 0.0_f32;
        for range in value.split(',') {
            let mut parts = range.split(';').map(str::trim);
            let media_type = parts.next().unwrap_or_default();
            let quality = parts
                .find_map(|part| part.strip_prefix("q="))
                .map_or(1.0, |value| value.parse::<f32>().unwrap_or(0.0));
            let quality = if (0.0..=1.0).contains(&quality) {
                quality
            } else {
                0.0
            };
            match media_type {
                JSON_CONTENT_TYPE => json_quality = json_quality.max(quality),
                SSZ_CONTENT_TYPE => ssz_quality = ssz_quality.max(quality),
                _ => {}
            }
        }
        if ssz_quality > 0.0 && ssz_quality >= json_quality {
            ContentType::Ssz
        } else {
            ContentType::Json
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_the_preferred_supported_representation() {
        for (accept, ssz) in [
            ("application/octet-stream", true),
            (
                "application/octet-stream;q=1.0,application/json;q=0.9",
                true,
            ),
            ("application/json,application/octet-stream;q=0.5", false),
            ("application/octet-stream;q=0", false),
            ("application/octet-stream;q=NaN", false),
            ("*/*", false),
        ] {
            let header = ActixHeaderValue::from_str(accept).unwrap();
            assert_eq!(
                matches!(ContentType::from(Some(&header)), ContentType::Ssz),
                ssz,
                "{accept}"
            );
        }
        assert!(matches!(ContentType::from(None), ContentType::Json));
    }
}
