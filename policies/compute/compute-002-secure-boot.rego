package terraform.policies.azure.compute_002

import future.keywords.in
import input.plan as tfplan

actions := [
	["no-op"],
	["create"],
	["update"],
]

resources := [resource_changes |
	resource_changes := tfplan.resource_changes[_]
	resource_changes.type in ["azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine"]
	resource_changes.mode == "managed"
	resource_changes.change.actions in actions
]

violations := [resource |
	resource := resources[_]
	not resource.change.after.secure_boot_enabled
]

violators[address] {
	address := violations[_].address
}

# METADATA
# title: AZURE-COMPUTE-002
# description: Ensure that secure boot is enabled
# custom:
#  severity: high
#  enforcement_level: mandatory
# authors:
# - name: Dan Barr
# organizations:
# - HashiCorp
rule[result] {
	count(violations) != 0
	result := {
		"policy": rego.metadata.rule().title,
		"description": rego.metadata.rule().description,
		"severity": rego.metadata.rule().custom.severity,
		"enforcement_level": rego.metadata.rule().custom.enforcement_level,
		"resources": {
			"count": count(violations),
			"addresses": violators,
		},
	}
}