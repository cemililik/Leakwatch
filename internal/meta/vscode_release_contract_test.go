package meta

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVSCodeMarketplaceWorkflow_FailsClosedOnRepositoryPolicy(t *testing.T) {
	path := filepath.Join("..", "..", ".github", "workflows", "vscode-release.yml")
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	workflow := string(contents)

	for _, contract := range []string{
		"inputs.publish && github.ref == 'refs/heads/main'",
		"environment: vscode-marketplace",
		"actions: read",
		"deployments: read",
		"prevent_self_review == true",
		"deployment_branch_policy.protected_branches == true",
		"VSCODE_ENV_AUDIT_TOKEN",
		"${{ secrets.VSCODE_ENV_AUDIT_TOKEN }}",
		"@<(printf 'Authorization: Bearer %s\\n' \"${GH_ENVIRONMENT_AUDIT_TOKEN:?}\")",
		"environments/vscode-marketplace/secrets/VSCE_PAT",
		".name == \"VSCE_PAT\"",
		"${{ secrets.VSCE_PAT }}",
		"${VSCE_PAT:?missing environment-scoped VSCE_PAT}",
		"npx --no-install vsce publish --packagePath",
		"if [[ ${#packages[@]} -ne 1 ]]",
	} {
		assert.Contains(t, workflow, contract)
	}
	assert.NotContains(t, workflow, "--pat")
	assert.NotContains(t, workflow, "Authorization: Bearer ${", "tokens must not be exposed in process arguments")
}
