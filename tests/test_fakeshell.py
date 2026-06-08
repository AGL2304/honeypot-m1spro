"""Tests du faux shell (cohérence des réponses, furtivité B6/B21)."""

from __future__ import annotations

from honeypots.common.fakeshell import FakeShell


def test_whoami_and_id_coherent():
    sh = FakeShell()
    assert sh.run("whoami") == "admin"
    assert "uid=1000(admin)" in sh.run("id")


def test_cat_passwd_returns_users():
    sh = FakeShell()
    out = sh.run("cat /etc/passwd")
    assert "root:x:0:0" in out
    assert "admin:x:1000:1000" in out


def test_uname_a_is_debian_like():
    sh = FakeShell()
    assert "Debian" in sh.run("uname -a")


def test_unknown_command():
    sh = FakeShell()
    assert "command not found" in sh.run("foobar123")


def test_cd_changes_prompt():
    sh = FakeShell()
    sh.run("cd /var/www")
    assert "/var/www" in sh.prompt


def test_exit_sentinel():
    sh = FakeShell()
    assert sh.run("exit") == "__EXIT__"
