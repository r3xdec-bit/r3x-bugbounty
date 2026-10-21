from typer.testing import CliRunner

from r3x.cli.main import app

runner = CliRunner()

def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "R3X-BugBounty" in result.output

def test_cli_doctor():
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "System Diagnostic Doctor" in result.output
    assert "Security Binaries Audit" in result.output

def test_cli_agents():
    result = runner.invoke(app, ["agents"])
    assert result.exit_code == 0
    assert "HermesMasterOrchestrator" in result.output
    assert "ScopeGuardianAgent" in result.output
    assert "FalsePositiveVerificationAgent" in result.output

def test_cli_mixer_status():
    result = runner.invoke(app, ["mixer", "status"])
    assert result.exit_code == 0
    assert "R3X AI Mixer Status" in result.output

def test_cli_project_flow():
    import uuid
    p_name = f"cli-proj-{uuid.uuid4().hex[:6]}"
    res = runner.invoke(app, ["project", "new", p_name, "--description", "CLI Project Test"])
    assert res.exit_code == 0
    assert "created successfully" in res.output

    res2 = runner.invoke(app, ["project", "list"])
    assert res2.exit_code == 0
    assert p_name in res2.output
