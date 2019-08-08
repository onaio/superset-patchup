import os
import shutil

def init_superset_for_testing():

	"""Basic initialization for all tests"""

	SUPERSET_TEST_HOME = os.path.join(os.path.dirname(__file__), '.superset')
	shutil.rmtree(SUPERSET_TEST_HOME, ignore_errors=True)
	os.environ['SUPERSET_HOME'] = SUPERSET_TEST_HOME
	os.environ['SUPERSET_CONFIG'] = 'tests.config.KETCHUP_CONFIG'

	# DRAGONS: don't import until ya got the home directory and config sorted
	import superset

	# Initialize Superset db
	superset.db.create_all()
	superset.utils.get_or_create_main_db()

	# Initialize test user and role
	test_role = superset.security_manager.add_role('test_role')
	superset.security_manager.get_session.commit()

	superset.security_manager.add_user(
	    'test_user', 'Test', 'User', 'test@user.org', test_role, password='password')
	superset.security_manager.get_session.commit()

init_superset_for_testing()
