// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#![cfg_attr(docsrs, feature(doc_cfg))]
//! Amazon S3 service implementation for Apache OpenDAL.
#![deny(missing_docs)]

mod backend;
mod config;
mod copier;
mod core;
mod deleter;
mod error;
mod lister;
mod writer;

pub use backend::S3Builder as S3;
pub use config::S3Config;

/// Default scheme for s3 service.
pub const S3_SCHEME: &str = "s3";

/// Parse one non-success S3 HTTP response with the exact upstream protocol
/// parser that the S3 backend itself uses.
///
/// This is the only public addition to the pinned `opendal-service-s3` 0.57.0
/// source. It exists so a transport adapter can classify a response body
/// (including provider error codes such as `NoSuchBucket`, `RequestTimeout`
/// and `OperationAborted`) without reimplementing any S3 XML semantics. The
/// returned error carries the upstream kind, temporary/permanent flags and the
/// upstream provider context; callers that must not retain provider text are
/// responsible for replacing the message and dropping the source before
/// exposing the error.
pub fn parse_error_response(resp: http::Response<opendal_core::Buffer>) -> opendal_core::Error {
    error::parse_error(resp)
}

/// Register this service into the given registry.
pub fn register_s3_service(registry: &opendal_core::OperatorRegistry) {
    registry.register::<S3>(S3_SCHEME);
}
