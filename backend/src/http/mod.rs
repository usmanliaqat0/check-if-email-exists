// Reacher - Email Verification
// Copyright (C) 2018-2023 Reacher

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

mod error;
mod v1;
mod version;

pub use v1::shared::CheckEmailRequest;

use crate::config::BackendConfig;
use check_if_email_exists::LOG_TARGET;
use error::handle_rejection;
pub use error::ReacherResponseError;
use std::env;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::info;
use warp::Filter;

pub fn create_routes(
	config: Arc<BackendConfig>,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
	version::get::get_version()
		.or(v1::check_email::post::v1_check_email(Arc::clone(&config)))
		.or(v1::bulk::post::v1_create_bulk_job(Arc::clone(&config)))
		.or(v1::bulk::get_progress::v1_get_bulk_job_progress(
			Arc::clone(&config),
		))
		.or(v1::bulk::get_results::v1_get_bulk_job_results(config))
		.recover(handle_rejection)
}

/// Runs the Warp server.
///
/// This function starts the Warp server and listens for incoming requests.
/// It returns a `Result` indicating whether the server started successfully or
/// encountered an error.
pub async fn run_warp_server(
	config: Arc<BackendConfig>,
) -> Result<(), anyhow::Error> {
	let host = config
		.http_host
		.parse::<IpAddr>()
		.unwrap_or_else(|_| panic!("Invalid host: {}", config.http_host));
	// For backwards compatibility, we allow the port to be set via the
	// environment variable PORT, instead of the new configuration file. The
	// PORT environment variable takes precedence.
	let port = env::var("PORT")
		.map(|port: String| {
			port.parse::<u16>()
				.unwrap_or_else(|_| panic!("Invalid port: {}", port))
		})
		.unwrap_or(config.http_port);

	let routes = create_routes(Arc::clone(&config));

	info!(target: LOG_TARGET, host=?host,port=?port, "Server is listening");
	warp::serve(routes).run((host, port)).await;

	Ok(())
}

/// The header which holds the Reacher backend secret.
pub const REACHER_SECRET_HEADER: &str = "x-reacher-secret";

/// Warp filter to check that the header secret is correct, if the header is
/// set in the config.
pub fn check_header(config: Arc<BackendConfig>) -> warp::filters::BoxedFilter<()> {
	if let Some(secret) = config.header_secret.clone() {
		if secret.is_empty() {
			return warp::any().boxed();
		}

		let secret: &'static str = Box::leak(Box::new(secret));

		warp::header::exact(REACHER_SECRET_HEADER, secret).boxed()
	} else {
		warp::any().boxed()
	}
}
