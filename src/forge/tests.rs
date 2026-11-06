use super::handlers::{IssuePage, IssueState, Page, title_valid, body_valid};
use crate::auth::idempotency_key;
use axum::{extract::Query, http::HeaderMap};

    #[test]
    fn issue_filter_query_contract() {
        for (query, expected) in [
            ("", None),
            ("?state=open", Some("open")),
            ("?state=closed&after=4&limit=2", Some("closed")),
        ] {
            let uri = format!("/issues{query}").parse().unwrap();
            let Query(page) = Query::<IssuePage>::try_from_uri(&uri).unwrap();
            assert_eq!(page.state.as_ref().map(IssueState::as_str), expected);
            assert!(page.bounds().is_ok());
        }
        for query in [
            "?state=",
            "?state=all",
            "?state=Open",
            "?state=open&state=closed",
            "?state=open&state=open",
            "?state=open&unknown=1",
        ] {
            let uri = format!("/issues{query}").parse().unwrap();
            assert!(Query::<IssuePage>::try_from_uri(&uri).is_err());
        }
        let uri = "/comments?state=open".parse().unwrap();
        assert!(Query::<Page>::try_from_uri(&uri).is_err());
        for query in [
            "?state=open&after=-1",
            "?state=closed&limit=0",
            "?state=open&limit=101",
        ] {
            let uri = format!("/issues{query}").parse().unwrap();
            let Query(page) = Query::<IssuePage>::try_from_uri(&uri).unwrap();
            assert!(page.bounds().is_err());
        }
    }

    #[test]
    fn idempotency_header_boundaries() {
        let mut headers = HeaderMap::new();
        assert_eq!(idempotency_key(&headers).unwrap(), None);
        for key in ["a".to_owned(), "A9._:-".to_owned(), "x".repeat(128)] {
            headers.insert("idempotency-key", key.parse().unwrap());
            assert_eq!(idempotency_key(&headers).unwrap(), Some(key.as_str()));
        }
        for key in [
            "".to_owned(),
            "x".repeat(129),
            "two words".to_owned(),
            "x,y".to_owned(),
            "x/y".to_owned(),
        ] {
            headers.insert("idempotency-key", key.parse().unwrap());
            assert!(idempotency_key(&headers).is_err());
        }
        headers.insert("idempotency-key", "one".parse().unwrap());
        headers.append("idempotency-key", "one".parse().unwrap());
        assert!(idempotency_key(&headers).is_err());
        headers.clear();
        headers.insert(
            "idempotency-key",
            axum::http::HeaderValue::from_bytes(b"nonascii\xff").unwrap(),
        );
        assert!(idempotency_key(&headers).is_err());
    }

    #[test]
    fn input_and_pagination_boundaries() {
        assert!(title_valid(&"a".repeat(256)));
        for bad in [
            "".into(),
            "  \t".into(),
            "a\nb".into(),
            "a\0b".into(),
            "a".repeat(257),
            "界".repeat(86),
        ] {
            assert!(!title_valid(&bad));
        }
        assert!(body_valid("", false));
        assert!(body_valid("line\n\ttwo\r\n", true));
        assert!(body_valid(&"x".repeat(8192), true));
        assert!(!body_valid(&"x".repeat(8193), true));
        assert!(!body_valid(" \n\t", true));
        assert!(!body_valid("bad\0value", false));
        assert_eq!(
            Page {
                after: None,
                limit: None
            }
            .bounds()
            .unwrap(),
            (0, 50)
        );
        for page in [
            Page {
                after: Some(-1),
                limit: None,
            },
            Page {
                after: None,
                limit: Some(0),
            },
            Page {
                after: None,
                limit: Some(101),
            },
        ] {
            assert!(page.bounds().is_err());
        }
    }
