terraform {
  required_providers {
    ponte = { source = "ponte-ai/ponte" }
  }
}

provider "ponte" {
  endpoint = "https://app.ponte.ai/api/control" # or PONTE_API_URL
  # token is read from PONTE_OPERATOR_TOKEN
}
