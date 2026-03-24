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

use check_if_email_exists::smtp::verif_method::{
	HotmailB2CVerifMethod, VerifMethod, VerifMethodSmtpConfig, YahooVerifMethod, DEFAULT_PROXY_ID,
};
use check_if_email_exists::{CheckEmailInput, CheckEmailInputProxy};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use warp::Filter;

use crate::config::BackendConfig;

/// The request body for the email verification endpoints.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct CheckEmailRequest {
	pub to_email: String,
	pub from_email: Option<String>,
	pub hello_name: Option<String>,
	pub proxy: Option<CheckEmailInputProxy>,
	pub smtp_timeout: Option<Duration>,
	pub smtp_port: Option<u16>,
	pub yahoo_verif_method: Option<V1YahooVerifMethod>,
	pub hotmailb2c_verif_method: Option<V1HotmailB2CVerifMethod>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub enum V1YahooVerifMethod {
	Api,
	#[default]
	Headless,
	Smtp,
}

impl V1YahooVerifMethod {
	pub fn to_yahoo_verif_method(
		&self,
		use_default_proxy: bool,
		hello_name: String,
		from_email: String,
		smtp_timeout: Option<Duration>,
		smtp_port: u16,
		retries: usize,
	) -> YahooVerifMethod {
		match self {
			Self::Api => YahooVerifMethod::Api,
			Self::Headless => YahooVerifMethod::Headless,
			Self::Smtp => YahooVerifMethod::Smtp(VerifMethodSmtpConfig {
				from_email,
				hello_name,
				smtp_port,
				smtp_timeout,
				proxy: if use_default_proxy {
					Some(DEFAULT_PROXY_ID.to_string())
				} else {
					None
				},
				retries,
			}),
		}
	}
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub enum V1HotmailB2CVerifMethod {
	#[default]
	Headless,
	Smtp,
}

impl V1HotmailB2CVerifMethod {
	pub fn to_hotmailb2c_verif_method(
		&self,
		use_default_proxy: bool,
		hello_name: String,
		from_email: String,
		smtp_timeout: Option<Duration>,
		smtp_port: u16,
		retries: usize,
	) -> HotmailB2CVerifMethod {
		match self {
			Self::Headless => HotmailB2CVerifMethod::Headless,
			Self::Smtp => HotmailB2CVerifMethod::Smtp(VerifMethodSmtpConfig {
				from_email,
				hello_name,
				smtp_port,
				smtp_timeout,
				proxy: if use_default_proxy {
					Some(DEFAULT_PROXY_ID.to_string())
				} else {
					None
				},
				retries,
			}),
		}
	}
}

impl CheckEmailRequest {
	pub fn to_check_email_input(&self, config: Arc<BackendConfig>) -> CheckEmailInput {
		let hello_name = self
			.hello_name
			.clone()
			.unwrap_or_else(|| config.hello_name.clone());
		let from_email = self
			.from_email
			.clone()
			.unwrap_or_else(|| config.from_email.clone());
		let smtp_timeout = self
			.smtp_timeout
			.or_else(|| config.smtp_timeout.map(Duration::from_secs));
		let smtp_port = self.smtp_port.unwrap_or(25);
		let retries = 1;

		let mut verif_method = if let Some(proxy) = &self.proxy {
			VerifMethod::new_with_same_config_for_all(
				Some(proxy.clone()),
				hello_name.clone(),
				from_email.clone(),
				smtp_port,
				smtp_timeout,
				retries,
			)
		} else {
			config.get_verif_method()
		};

		if let Some(yahoo_verif_method) = &self.yahoo_verif_method {
			verif_method.yahoo = yahoo_verif_method.to_yahoo_verif_method(
				self.proxy.is_some(),
				hello_name.clone(),
				from_email.clone(),
				smtp_timeout,
				smtp_port,
				retries,
			);
		}
		if let Some(hotmailb2c_verif_method) = &self.hotmailb2c_verif_method {
			verif_method.hotmailb2c = hotmailb2c_verif_method.to_hotmailb2c_verif_method(
				self.proxy.is_some(),
				hello_name,
				from_email,
				smtp_timeout,
				smtp_port,
				retries,
			);
		}

		CheckEmailInput {
			to_email: self.to_email.clone(),
			verif_method,
			sentry_dsn: config.sentry_dsn.clone(),
			backend_name: config.backend_name.clone(),
			webdriver_config: config.webdriver.clone(),
			..Default::default()
		}
	}
}

/// Warp filter that adds the BackendConfig to the handler.
pub fn with_config(
	config: Arc<BackendConfig>,
) -> impl Filter<Extract = (Arc<BackendConfig>,), Error = std::convert::Infallible> + Clone {
	warp::any().map(move || Arc::clone(&config))
}
