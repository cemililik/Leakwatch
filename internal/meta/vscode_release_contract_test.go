package meta

import (
	"os"
	"path/filepath"
	"strings"
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
		"npx --no-install vsce publish --packagePath",
		"if [[ ${#packages[@]} -ne 1 ]]",
	} {
		assert.Contains(t, workflow, contract)
	}
	assert.NotContains(t, workflow, "--pat")
	assert.NotContains(t, workflow, "$VSCE_PAT")
	assert.Equal(t, 2, strings.Count(workflow, "VSCE_PAT"), "PAT may appear only as the environment key and environment-secret reference")
}
