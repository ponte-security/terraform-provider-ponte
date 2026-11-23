terraform {
  required_providers {
    ponte = { source = "ponte-security/ponte" }
  }
}

provider "ponte" {
  endpoint = "https://api.ponte.ai/control" # or PONTE_API_URL
  # Sign-in comes from the environment: PONTE_OPERATOR_TOKEN (a person),
  # PONTE_IDENTITY_ID (a pipeline's own identity) or PONTE_API_KEY.
}
