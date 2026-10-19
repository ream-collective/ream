use std::str::FromStr;

use actix_web::{HttpRequest, Responder, get, web};
use actix_web_lab::sse;
use futures::stream;
use ream_api_types_common::error::ApiError;
use ream_events_beacon::{BeaconEvent, EventTopic};
use tokio::sync::broadcast;

/// Reads `topics` given as a comma-separated list, as repeated parameters, or both.
fn parse_topics(query: &str) -> Result<Vec<String>, ApiError> {
    let topics = url::form_urlencoded::parse(query.as_bytes())
        .filter(|(key, _)| key == "topics")
        .flat_map(|(_, value)| {
            value
                .split(',')
                .map(|topic| topic.trim().to_string())
                .collect::<Vec<_>>()
        })
        .filter(|topic| !topic.is_empty())
        .collect::<Vec<_>>();
    if topics.is_empty() {
        return Err(ApiError::BadRequest("Missing topics".into()));
    }
    for topic in &topics {
        EventTopic::from_str(topic)
            .map_err(|err| ApiError::BadRequest(format!("Invalid topic: {err}")))?;
    }
    Ok(topics)
}

#[get("/events")]
pub async fn get_events(
    request: HttpRequest,
    event_sender: web::Data<broadcast::Sender<BeaconEvent>>,
) -> Result<impl Responder, ApiError> {
    let topics = parse_topics(request.query_string())?;

    let rx = event_sender.subscribe();

    let stream = stream::unfold(rx, move |mut rx| {
        let topics = topics.clone();
        async move {
            loop {
                let event = match rx.recv().await {
                    Ok(event) => event,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        return None;
                    }
                };

                let event_name = event.event_name();
                if !topics.contains(&event_name.to_string()) {
                    continue;
                }

                match event.serialize_data() {
                    Ok(json_data) => {
                        let sse_event =
                            sse::Event::Data(sse::Data::new(json_data).event(event_name));
                        return Some((Ok::<_, actix_web::Error>(sse_event), rx));
                    }
                    Err(err) => {
                        tracing::warn!("Failed to serialize event {event_name}: {err}");
                        continue;
                    }
                }
            }
        }
    });

    Ok(sse::Sse::from_stream(stream).with_keep_alive(std::time::Duration::from_secs(10)))
}

#[cfg(test)]
mod tests {
    use super::parse_topics;

    #[test]
    fn topics_accept_comma_lists_and_repeated_parameters() {
        assert_eq!(parse_topics("topics=head").unwrap(), ["head"]);
        assert_eq!(
            parse_topics("topics=head,block").unwrap(),
            ["head", "block"]
        );
        assert_eq!(
            parse_topics("topics=head&topics=block").unwrap(),
            ["head", "block"]
        );
        assert_eq!(
            parse_topics("topics=head%2Cblock").unwrap(),
            ["head", "block"]
        );
        assert!(parse_topics("topics=nope").is_err());
        assert!(parse_topics("").is_err());
    }
}
