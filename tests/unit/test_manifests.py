from lineage_core.manifests import baseline_entities, candidate_entities, is_manifest, mentions_manifest
from lineage_core.models import EntityRecord, SourceTier


def test_package_json_dependencies():
    text = '{"name": "x", "dependencies": {"left-pad": "1"}, "devDependencies": {"@scope/Tool": "^2"}, "scripts": {"test": "node --test"}}'
    assert baseline_entities("/w/package.json", text) == {"pkg:npm:left-pad", "pkg:npm:@scope/tool"}


def test_package_lock_packages():
    text = '{"packages": {"": {}, "node_modules/left-pad": {}, "node_modules/a/node_modules/@s/b": {}}}'
    assert baseline_entities("package-lock.json", text) == {"pkg:npm:left-pad", "pkg:npm:@s/b"}


def test_requirements_and_pyproject():
    assert baseline_entities("requirements-dev.txt", "requests==2.32\n# c\n-r base.txt\nhttpx[http2]>=0.27\n") == {
        "pkg:pypi:requests",
        "pkg:pypi:httpx",
    }
    pyproject = '[project]\ndependencies = ["fastapi>=0.1", "PyYAML"]\n[project.optional-dependencies]\ndev = ["pytest"]\n'
    assert baseline_entities("pyproject.toml", pyproject) == {"pkg:pypi:fastapi", "pkg:pypi:pyyaml", "pkg:pypi:pytest"}


def test_broken_manifest_yields_nothing_instead_of_raising():
    assert baseline_entities("package.json", "{not json") == set()


def test_candidates_ignore_ordinary_package_json_fields():
    fragment = '"name": "orders-api", "main": "src/index.js", "test": "node --test", "is-even": "^1.0.0", "@a/b": "latest"'
    assert candidate_entities(fragment) == {"pkg:npm:is-even", "pkg:npm:@a/b"}


def test_candidates_from_shell_commands():
    assert candidate_entities("npm pkg set devDependencies.evil-pkg=1.0.0") == {"pkg:npm:evil-pkg"}
    assert candidate_entities("echo 'evil==1.0' >> requirements.txt", "requirements.txt") == {"pkg:pypi:evil"}


def test_manifest_detection():
    assert is_manifest("/workspace/sub/package.json")
    assert is_manifest("requirements-dev.txt")
    assert not is_manifest("/workspace/src/package.js")
    assert mentions_manifest("sed -i 's/a/b/' ./package.json")
    assert not mentions_manifest("cat README.md")


def test_workspace_content_cannot_raise_an_untrusted_name():
    record = EntityRecord(entity="pkg:npm:x", best_tier=SourceTier.UNTRUSTED)
    record.observe(SourceTier.UNTRUSTED, "issue")
    record.observe(SourceTier.CHECKED, "notes")
    assert record.best_tier == SourceTier.UNTRUSTED
    record.observe(SourceTier.TRUSTED, "user")
    assert record.best_tier == SourceTier.TRUSTED


def test_name_seen_in_the_workspace_first_stays_checked():
    record = EntityRecord(entity="pkg:npm:x", best_tier=SourceTier.CHECKED)
    record.observe(SourceTier.CHECKED, "readme")
    record.observe(SourceTier.UNTRUSTED, "issue")
    assert record.best_tier == SourceTier.CHECKED
