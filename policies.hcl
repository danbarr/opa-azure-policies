# Compute policies
policy "Linux-VM-Size" {
  query = "data.terraform.policies.azure.compute_001.rule"
  enforcement_level = "advisory"
}

policy "Secure-Boot" {
  query = "data.terraform.policies.azure.compute_002.rule"
  enforcement_level = "mandatory"
}

policy "Legacy-VM-Resource" {
  query = "data.terraform.policies.azure.compute_003.rule"
  enforcement_level = "mandatory"
}

policy "Approved-Extensions" {
  query = "data.terraform.policies.azure.compute_004.rule"
  enforcement_level = "mandatory"
}

# Networking policies
policy "Restrict-RDP-SSH" {
  query = "data.terraform.policies.azure.network_001.rule"
  enforcement_level = "mandatory"
}
