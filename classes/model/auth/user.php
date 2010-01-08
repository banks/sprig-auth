<?php defined('SYSPATH') or die ('No direct script access.');
/**
 * Sprig Auth User Model
 * @package Sprig Auth
 * @author	Paul Banks
 */
class Model_Auth_User extends Sprig
{
	protected $_title_key = 'username';

	protected $_sorting = array('username' => 'asc');

	protected function _init()
	{
		$this->_fields += array(
			'id' => new Sprig_Field_Auto,
			'username' => new Sprig_Field_Char(array(
				'empty'  => FALSE,
				'unique' => TRUE,
				'max_length' => 32,
				'rules'  => array(
					'regex' => array('/^[\pL_.-]+$/ui')
				),
			)),
			'password' => new Sprig_Field_Password(array(
				'empty' => FALSE,
				'hash_with' => array(Auth::instance(), 'hash_password'),
			)),
			'password_confirm' => new Sprig_Field_Password(array(
				'empty' => TRUE,
				'in_db' => FALSE,
				'hash_with' => NULL,
				'callbacks' => array(
					'matches' => array($this, '_check_password_matches'),
				),
			)),
			'email' => new Sprig_Field_Email(array(
				'unique' => TRUE,
				'empty' => FALSE,
				'max_length' => 127
			)),
			'logins' => new Sprig_Field_Integer(array(
				'empty' => TRUE,
				'editable' => FALSE,
			)),
			'last_login' => new Sprig_Field_Timestamp(array(
				'empty' => TRUE,
				'editable' => FALSE,
			)),
			'tokens' => new Sprig_Field_HasMany(array(
				'model' => 'User_Token',
				'editable' => FALSE,
			)),
			'roles' => new Sprig_Field_ManyToMany(array(
				'model' => 'Role',
				'through' => 'roles_users',
			)),
		);
	}
	
	/**
	 * Convenience factory for getting user by any unique key
	 * @param mixed string unique key (email or username), or integer id
	 * @param array	dummy param to make method compatible with Sprig::factory
	 * @return Model_Auth_User
	 */
	public static function factory($username, array $dummy = NULL)
	{
		$user = parent::factory('User');
		return $user->values(array($user->unique_key($username) => $username));
	}
	
	/**
	 * Allow serialization of initialized object containing related objects as a Database_Result
	 * 
	 * @return array	list of properties to serialize
	 */
	public function __sleep()
	{
		foreach ($this->_related as $field => $object)
		{
			if ($object instanceof Database_Result)
			{
				if ($object instanceof Database_Result_Cached)
				{
					continue;
				}
				
				// Convert result object to cached result to allow for serialization
				// Currently no way to get the $_query property form the result to pass to the cached result
				// @see http://dev.kohanaphp.com/issues/2297
				
				$this->_related[$field] = new Database_Result_Cached($object->as_array(), '', get_class(Sprig::factory($field->model)));			
			}
		}		
		
		// Return array of all properties to get them serialised
		$props = array();
		
		foreach ($this as $prop => $val)
		{
			$props[] = $prop;
		}
		
		return $props;
	}
	
	/**
	 * Validate callback wrapper for checking password match
	 * @param Validate $array
	 * @param string   $field
	 * @return void
	 */
	public function _check_password_matches(Validate $array, $field)
	{
		$auth = Auth::instance();
		
		$salt = $auth->find_salt($array['password']);		
		
		if ($array['password'] !== $auth->hash_password($array[$field], $salt))
		{
			// Re-use the error messge from the 'matches' rule in Validate
			$array->error($field, 'matches', array('param1' => 'password'));
		}
	}
	
	/**
	 * Check if user has a particular role
	 * @param mixed $role 	Role to test for, can be Model_Role object, string role name of integer role id
	 * @return bool			Whether or not the user has the requested role
	 */
	public function has_role($role)
	{
		// Check what sort of argument we have been passed
		if ($role instanceof Model_Role)
		{
			$key = 'id';
			$val = $role->id;
		}
		elseif (is_string($role))
		{
			$key = 'name';
			$val = $role;
		}
		else
		{
			$key = 'id';
			$val = (int) $role;
		}
		
		foreach ($this->roles as $user_role)
		{
			if ($user_role->{$key} === $val)
			{
				return TRUE;
			}
		}
		
		return FALSE;
	}
	
	/**
	 * Get unique key based on value
	 * @param mixed $value	Kay value for match
	 * @return string		Unique key name to attempt to match against
	 */
	public function unique_key($value)
	{
		if (Validate::email($value))
		{
			return 'email';
		} 
		elseif (is_string($value))
		{
			return 'username';
		}
		return 'id';
	}
	
} // End Model_Auth_User