from ours.benchmark.prompts import ARM_PROMPTS

WORKERS = {"reader", "emailer", "secrets_manager"}


def test_both_arms_define_every_worker():
    assert set(ARM_PROMPTS) == {"A", "B"}
    for arm in ARM_PROMPTS.values():
        assert set(arm) == WORKERS


def test_arm_b_only_adds_wording_to_arm_a():
    for name in WORKERS:
        assert ARM_PROMPTS["B"][name].startswith(ARM_PROMPTS["A"][name])
        assert len(ARM_PROMPTS["B"][name]) > len(ARM_PROMPTS["A"][name])
