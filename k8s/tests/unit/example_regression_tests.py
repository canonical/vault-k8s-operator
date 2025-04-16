import ops.testing as testing
from tests.unit.fixtures import MockBinding, VaultCharmFixtures


class TestRegression(VaultCharmFixtures):
    # This test case copies all of the parts required to create the correct state so the action can run
    def test_regression_authorize_charm_action_1(self):
        self.mock_vault.configure_mock(
            **{
                "authenticate.return_value": True,
                "create_or_update_approle.return_value": "my-role-id",
                "generate_role_secret_id.return_value": "my-secret-id",
            },
        )
        self.mock_get_binding.return_value = MockBinding(
            bind_address="1.2.3.4",
            ingress_address="1.2.3.4",
        )
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        user_provided_secret = testing.Secret(
            tracked_content={"token": "my token"},
        )
        state_in = testing.State(
            containers=[container],
            leader=True,
            secrets=[user_provided_secret],
        )
        self.ctx.run(
            self.ctx.on.action("authorize-charm", params={"secret-id": user_provided_secret.id}),
            state=state_in,
        )
        # Nothing to assert, if the action runs without raising an exception, the test passes
        # if any part of the public interface of the action changes, an exception will be raised
        # and the test will fail

    # An alternative way to write the same test that only runs the action, if the name of the action was changed
    # the name of the parameter was changed or its type was changed, scenario will raise an InconsistentScenarioError
    # and the test will fail
    # otherwise the test will pass, even if the action fails to run and a RuntimeError or something else is raised
    def test_regression_authorize_charm_action_2(self):
        try:
            self.ctx.run(
                self.ctx.on.action("authorize-charm", params={"secret-id": "my-secret-id"}),
                state=testing.State(),
            )
        except testing.errors.InconsistentScenarioError:
            raise
        except Exception:
            pass

    def test_regression_authorize_charm_action_that_fails_because_the_type_is_wrong(self):
        try:
            self.ctx.run(
                self.ctx.on.action("authorize-charm", params={"secret-id": 33}),
                state=testing.State(),
            )
        except testing.errors.InconsistentScenarioError:
            raise
        except Exception:
            pass
