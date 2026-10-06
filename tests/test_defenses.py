import pytest

from agent.defenses import DEFENSES, get_defense


def test_expected_defenses_are_registered():
    assert set(DEFENSES) == {
        "baseline",
        "authorization",
        "prompt_guard",
        "layered",
    }


@pytest.mark.parametrize(
    ("name", "requires_authorization"),
    [
        ("baseline", False),
        ("authorization", True),
        ("prompt_guard", False),
        ("layered", True),
    ],
)
def test_authorization_requirement(name, requires_authorization):
    defense = get_defense(name)

    assert defense.name == name
    assert defense.requires_authorization() is requires_authorization


def test_baseline_does_not_add_prompt_defense():
    assert get_defense("baseline").system_instruction() == ""


def test_authorization_does_not_add_prompt_defense():
    assert get_defense("authorization").system_instruction() == ""


def test_prompt_guard_adds_security_instruction():
    instruction = get_defense("prompt_guard").system_instruction()

    assert instruction
    assert "untrusted" in instruction.lower()
    assert "authorization" in instruction.lower()


def test_layered_uses_prompt_guard_instruction():
    assert (
        get_defense("layered").system_instruction()
        == get_defense("prompt_guard").system_instruction()
    )


def test_unknown_defense_fails_closed():
    with pytest.raises(ValueError, match="Unknown defense"):
        get_defense("does-not-exist")