<?php

/**
 * @file
 * Provide Auth request, Callback, User Registration, Account settings tab page.
 */

/**
 * Generate Naver login auth request.
 *
 * API Spec : http://developer.naver.com/wiki/pages/NaverLogin_spec .
 */
function naver_login_auth_request() {

  $naver_login_client_id = NULL;
  $naver_login_request_uri = variable_get('naver_login_callback_uri', NULL);

  if (user_is_logged_in() && !isset($_SESSION['naver_login_loggedin_user_want_connect'])) {
    drupal_goto();
  }

  if ((bool) variable_get('naver_login_client_id', FALSE) && (bool) variable_get('naver_login_client_secret', FALSE)) {
    $naver_login_client_id = variable_get('naver_login_client_id', NULL);
    $naver_login_request_uri = variable_get('naver_login_callback_uri', NULL);
  }
  else {
    drupal_goto();
  }

  // Generate state token TO prevent CSRF exploit.
  $naver_login_state_token = md5(drupal_random_bytes(32));
  $_SESSION['naver_login']['naver_login_state_token'] = $naver_login_state_token;

  $http_params = array(
    'response_type' => 'code',
    'client_id' => $naver_login_client_id,
    'state' => $naver_login_state_token,
    'redirect_uri' => $naver_login_request_uri,
  );

  $naver_login_service_request_uri = 'https://nid.naver.com/oauth2.0/authorize?' . http_build_query($http_params);

  drupal_goto($naver_login_service_request_uri);
}

/**
 * Callback - Retrieve Naver login Auth context.
 */
function naver_login_auth_retrieve() {
  $naver_login_client_id = NULL;
  $naver_login_client_secret = NULL;

  if (user_is_logged_in() && !isset($_SESSION['naver_login_loggedin_user_want_connect'])) {
    drupal_goto();
  }

  if ((bool) variable_get('naver_login_client_id', FALSE) && (bool) variable_get('naver_login_client_secret', FALSE)) {
    $naver_login_client_id = variable_get('naver_login_client_id', NULL);
    $naver_login_client_secret = variable_get('naver_login_client_secret', NULL);
  }
  else {
    drupal_goto();
  }

  if (!isset($_GET['code']) || !isset($_GET['state']) || !isset($_SESSION['naver_login']['naver_login_state_token'])) {
    drupal_goto();
  }

  if ($_GET['state'] != $_SESSION['naver_login']['naver_login_state_token']) {
    // If invalid -> unset token and goto main page.
    unset($_SESSION['naver_login']['naver_login_state_token']);
    drupal_goto();
  }

  /*
    Step 1. Retrieve ACCESS TOKEN using $_GET['code'] value.
   */

  $http_params = array(
    'grant_type' => 'authorization_code',
    'client_id' => $naver_login_client_id,
    'client_secret' => $naver_login_client_secret,
    'code' => $_GET['code'],
    'state' => $_SESSION['naver_login']['naver_login_state_token'],
  );

  $curl_opt = array(
    CURLOPT_URL => 'https://nid.naver.com/oauth2.0/token',
    CURLOPT_POST => TRUE,
    CURLOPT_POSTFIELDS => http_build_query($http_params),
    CURLOPT_RETURNTRANSFER => TRUE,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_TIMEOUT => 10,
    CURLOPT_HTTPHEADER => array(
      "Host: nid.naver.com",
      "Pragma: no-cache",
      "Accept: */*",
    ),
  );

  $curl_connection = curl_init();
  curl_setopt_array($curl_connection, $curl_opt);
  $curl_results = curl_exec($curl_connection);
  curl_close($curl_connection);

  $curl_results_obj = json_decode($curl_results);

  if ($curl_results_obj == NULL || isset($curl_results_obj->error)) {
    // Error.
    drupal_goto();
  }
  else {
    // Success.
    $naver_login_access_user_access_token = $curl_results_obj->access_token;
  }

  /*
    Step 2. Retrieve ACCESS TOKEN using $_GET['code'] value.
   */

  $curl_auth_header = "Authorization: Bearer " . $naver_login_access_user_access_token;

  $curl_opt = array(
    CURLOPT_URL => "https://apis.naver.com/nidlogin/nid/getUserProfile.xml",
    CURLOPT_POST => TRUE,
    CURLOPT_RETURNTRANSFER => TRUE,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_TIMEOUT => 10,
    CURLOPT_HTTPHEADER => array(
      "Host: apis.naver.com",
      "Pragma: no-cache",
      "Accept: */*",
      $curl_auth_header,
    ),
  );

  $curl_connection = curl_init();
  curl_setopt_array($curl_connection, $curl_opt);
  $curl_results = curl_exec($curl_connection);
  curl_close($curl_connection);

  $user_profile_xml = simplexml_load_string($curl_results, 'SimpleXMLElement', LIBXML_NOCDATA);

  if ($user_profile_xml == NULL
    || !isset($user_profile_xml->result)
    || !isset($user_profile_xml->result->resultcode)
    || $user_profile_xml->result->resultcode != '00') {

    // Error.
    drupal_goto();
  }

  /*
    Step 3. Processing user profile.
   */
  $user_profile_array = json_decode(json_encode($user_profile_xml), TRUE);

  $naver_userinfo_enc_id = $user_profile_array['response']['enc_id'];
  $naver_userinfo_email = $user_profile_array['response']['email'];

  $drupal_uid = naver_login_get_drupal_uid_by_naver_enc_id($naver_userinfo_enc_id);

  if ($drupal_uid) {
    $exist_user = user_load($drupal_uid);

    if (!$exist_user) {
      naver_login_revoke_connection($drupal_uid);
      $drupal_uid = NULL;
      $exist_user = NULL;
    }
  }

  if (user_is_logged_in() && isset($_SESSION['naver_login_loggedin_user_want_connect'])) {
    global $user;

    if ($user->mail == $naver_userinfo_email) {
      naver_login_make_connection($user->uid, $naver_userinfo_enc_id, $user_profile_array);
      drupal_set_message(t('Account has been Successfully connected with Naver.'));
    }
    else {
      drupal_set_message(t('Your account email is differ from Naver account. connection failed.'), 'error');
    }

    unset($_SESSION['naver_login_loggedin_user_want_connect']);
    drupal_goto('user/' . $user->uid . '/edit/naver_login');
  }

  // If already connected,
  if ($drupal_uid) {
    // User already registered Naver account to site, log them in.
    $form_state['uid'] = $drupal_uid;
    user_login_submit(array(), $form_state);

    // Need to redirect destination.
    drupal_goto('user');
  }
  elseif ($account_id = naver_login_email_already_exist($naver_userinfo_email)) {
    // The user was not found in the users table, but the.
    // Email from Naver might already have an account.
    $account_info = user_load($account_id);

    // Redirect user to the login page with a message..
    drupal_set_message(t('This email address is already registered to an account. <br />You can connect in user settings form.<br />Account Username : @accountID', array('@accountID' => $account_info->name)));
    $options = array(
      'query' => array(
        'naver_login' => 'true',
      ),
    );
    drupal_goto('user/login', $options);
  }
  else {

    $_SESSION[$_GET['state']]['user_profile'] = serialize($user_profile_array);

    drupal_goto('naver_login/auth/register',
      array(
        'query' => array(
          'state' => $_GET['state'],
        ),
      )
    );

  }
}

/**
 * Custom User Registration page.
 */
function naver_login_auth_register($form, &$form_state) {

  drupal_set_title(t('Sign Up with Naver Account'));

  if (!isset($_GET['state'])
    || !isset($_SESSION['naver_login']['naver_login_state_token'])
    || !isset($_SESSION[$_GET['state']]['user_profile'])) {
    drupal_goto();
  }

  if ($_GET['state'] != $_SESSION['naver_login']['naver_login_state_token']) {
    // If invalid -> unset token and goto main page.
    unset($_SESSION['naver_login']['naver_login_state_token']);
    drupal_goto();
  }

  $user_profile_array = unserialize($_SESSION[$_GET['state']]['user_profile']);

  $naver_userinfo_email = $user_profile_array['response']['email'];
  $naver_userinfo_nickname = $user_profile_array['response']['nickname'];
  $naver_userinfo_enc_id = $user_profile_array['response']['enc_id'];

  $drupal_uid = naver_login_get_drupal_uid_by_naver_enc_id($naver_userinfo_enc_id);
  if ($drupal_uid) {
    drupal_access_denied();
    return;
  }

  // Registration.
  $form = drupal_retrieve_form('user_register_form', $form_state);

  // Prevent users registration if admin has blocked free registration.
  $user_reg_mode = variable_get('user_register', 1);
  if ($user_reg_mode == 0) {
    drupal_access_denied();
    return;
  }

  $form['account']['name']['#value'] = empty($form_state['values']['name']) ? $naver_userinfo_nickname : $form_state['values']['name'];
  $form['account']['mail']['#value'] = empty($form_state['values']['mail']) ? $naver_userinfo_email : $form_state['values']['mail'];

  $form['#validate'][] = 'naver_login_register_form_validate';
  $form['#submit'][] = 'naver_login_register_form_submit';

  return $form;

}

/**
 * Check Auth session valid or Not.
 */
function naver_login_register_form_validate($form, &$form_state) {
  if (!isset($_GET['state'])
    || !isset($_SESSION['naver_login']['naver_login_state_token'])
    || !isset($_SESSION[$_GET['state']]['user_profile'])
    || $_GET['state'] != $_SESSION['naver_login']['naver_login_state_token']
    ) {

    drupal_set_message(t('Your session has been expired. Please try Naver Login again.'), 'error');
    drupal_goto('user');
  }

}

/**
 * After validation.
 */
function naver_login_register_form_submit($form, &$form_state) {
  $user_profile_array = unserialize($_SESSION[$_GET['state']]['user_profile']);

  $naver_userinfo_enc_id = $user_profile_array['response']['enc_id'];

  $drupal_uid = naver_login_get_drupal_uid_by_naver_enc_id($naver_userinfo_enc_id);

  // If already connected.
  if ($drupal_uid) {
    drupal_set_message(t('Retrying registration. Your Naver account is already assigned to one account on our site.'), 'error');
    watchdog('naver_login', 'Error creating account for @naver_userinfo_enc_id', array('@naver_userinfo_enc_id' => $naver_userinfo_enc_id), WATCHDOG_ALERT);
    drupal_goto();
  }

  $user = $form_state['user'];

  if (!$user) {
    drupal_set_message(t('Error saving user account.'), 'error');
    drupal_goto();
  }

  naver_login_make_connection($user->uid, $naver_userinfo_enc_id, $user_profile_array);

  unset($_SESSION[$_GET['state']]);
  unset($_SESSION['naver_login']['naver_login_state_token']);

  drupal_goto('user');
}

/**
 * This form allows the user to manage their Naver Account Connection.
 *
 * Only admin can view account's Auth details.
 */
function naver_login_user_settings_form($form, $form_state, $account) {

  $is_admin = FALSE;

  if (user_access('administer users')) {
    $is_admin = TRUE;
  }

  $naver_login_additional_data = naver_login_get_additional_data_by_uid($account->uid);
  $is_account_connected = FALSE;
  if ($naver_login_additional_data) {
    $is_account_connected = TRUE;
  }

  $form['naver_login'] = array(
    '#title' => t('Naver Login info (ADMIN VIEW)'),
    '#type' => 'fieldset',
    '#description' => t('The data received from Naver.<br />Only admin can view this info.<br />Data will be removed when Naver account disconnect. (also drupal user account cancelation)<br /><br />'),
    '#access' => $is_admin,
  );

  $form['naver_login']['naver_enc_id'] = array(
    '#type' => 'textfield',
    '#title' => t('User Encrypted ID'),
    '#default_value' => $is_account_connected ? $naver_login_additional_data['naver_enc_id'] : '',
    '#disabled' => TRUE,
    '#access' => $is_admin,
  );

  $form['naver_login']['naver_email'] = array(
    '#type' => 'textfield',
    '#title' => t('User Email'),
    '#default_value' => $is_account_connected ? $naver_login_additional_data['naver_email'] : '',
    '#disabled' => TRUE,
    '#access' => $is_admin,
  );

  $form['naver_login']['naver_nickname'] = array(
    '#type' => 'textfield',
    '#title' => t('User Nickname'),
    '#default_value' => $is_account_connected ? $naver_login_additional_data['naver_nickname'] : '',
    '#disabled' => TRUE,
    '#access' => $is_admin,
  );

  $form['naver_login']['naver_profile_image'] = array(
    '#type' => 'textfield',
    '#title' => t('User Profile Image'),
    '#default_value' => $is_account_connected ? $naver_login_additional_data['naver_profile_image'] : '',
    '#disabled' => TRUE,
    '#access' => $is_admin,
  );

  $form['naver_login']['naver_age'] = array(
    '#type' => 'textfield',
    '#title' => t('User Age'),
    '#default_value' => $is_account_connected ? $naver_login_additional_data['naver_age'] : '',
    '#disabled' => TRUE,
    '#access' => $is_admin,
  );

  $form['naver_login']['naver_birthday'] = array(
    '#type' => 'textfield',
    '#title' => t('User Birthday'),
    '#default_value' => $is_account_connected ? $naver_login_additional_data['naver_birthday'] : '',
    '#disabled' => TRUE,
    '#access' => $is_admin,
  );

  $form['naver_login']['gender'] = array(
    '#type' => 'textfield',
    '#title' => t('User Gender'),
    '#default_value' => $is_account_connected ? $naver_login_additional_data['gender'] : '',
    '#disabled' => TRUE,
    '#access' => $is_admin,
  );

  $form['account'] = array(
    '#type' => 'value',
    '#value' => $account,
  );

  $form['naver_login_connect'] = array(
    '#title' => t('Naver account connect (auto login)'),
    '#type' => 'fieldset',
    '#description' => $is_account_connected ? t('This account connected with <em>@naver_mail</em>.', array('@naver_mail' => $naver_login_additional_data['naver_email'])) : t('If you want connect this account and naver account, Click Connect button below.'),
  );

  if ($is_account_connected) {
    $form['naver_login_connect']['disconnect'] = array(
      '#type' => 'submit',
      '#value' => t('Disconnect'),
      '#submit' => array('naver_login_request_revoke'),
    );
  }
  else {
    $form['naver_login_connect']['connect'] = array(
      '#type' => 'submit',
      '#value' => t('Connect'),
      '#disabled' => $is_admin ? TRUE : FALSE,
      '#submit' => array('naver_login_request_connect'),
    );
  }

  return $form;
}

/**
 * Callback Connect.
 */
function naver_login_request_connect($form, &$form_state) {
  $_SESSION['naver_login_loggedin_user_want_connect'] = TRUE;
  drupal_goto('naver_login/auth/request');
}

/**
 * Callback Disconnect.
 */
function naver_login_request_revoke($form, &$form_state) {
  $account = $form_state['values']['account'];
  naver_login_revoke_connection($account->uid);

  drupal_set_message(t('Account has been disconnected with Naver.'));
}

/**
 * Menu callback identities.
 */
function naver_login_user_identities($form_id, $account) {
  return drupal_get_form('naver_login_user_settings_form', $account);
}
