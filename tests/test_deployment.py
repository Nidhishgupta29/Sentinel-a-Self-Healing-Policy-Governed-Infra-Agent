from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_deployment_files_include_both_services_and_bundled_history():
    compose = (PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "dashboard:" in compose
    assert "demo_app:" in compose
    assert "dashboard.app:app" in compose
    assert "demo_app.main:app" in compose
    assert '"8000:8000"' in compose
    assert '"8001:8000"' in compose
    for path in ("dashboard", "demo_app", "sentinel", "postmortems", "evals"):
        assert f"COPY {path} " in dockerfile


def test_required_deployment_commands_and_smoke_script_exist():
    makefile = (PROJECT_ROOT / "Makefile").read_text(encoding="utf-8")
    smoke_test = (PROJECT_ROOT / "scripts" / "smoke_test.sh").read_text(encoding="utf-8")

    for target in ("test", "eval", "up", "demo"):
        assert f"{target}:" in makefile
    assert "docker compose up --build" in makefile
    assert "docker compose up -d --build" in smoke_test
    assert "docker compose down" in smoke_test
    assert "postmortem" in smoke_test


def test_render_blueprint_targets_dashboard_and_bundles_history():
    render = (PROJECT_ROOT / "render.yaml").read_text(encoding="utf-8")
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "type: web" in render
    assert "runtime: docker" in render
    assert "plan: free" in render
    assert "dockerfilePath: ./Dockerfile" in render
    assert "healthCheckPath: /" in render
    assert "dashboard.app:app" in dockerfile
    assert "--host 0.0.0.0" in dockerfile
    assert "${PORT:-8000}" in dockerfile
