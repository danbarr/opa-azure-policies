# Compute policies
policy "azure_compute_001" {
  query = "data.terraform.policies.azure.compute_001.rule"
  enforcement_level = "advisory"
}

policy "azure_compute_002" {
  query = "data.terraform.policies.azure.compute_002.rule"
  enforcement_level = "mandatory"
}

policy "azure_compute_003" {
  query = "data.terraform.policies.azure.compute_003.rule"
  enforcement_level = "mandatory"
}

policy "azure_compute_004" {
  query = "data.terraform.policies.azure.compute_004.rule"
  enforcement_level = "mandatory"
}

# Networking policies
policy "azure_network_001" {
  query = "data.terraform.policies.azure.network_001.rule"
  enforcement_level = "mandatory"
}