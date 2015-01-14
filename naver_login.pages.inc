<?php

/**
 * @file
 * Provide syndication pages for the module.
 */

/**
 * Generate naver login service request context.
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

  header('Location: ' . $naver_login_service_request_uri);
}

/**
 * Retrieve naver login service response context.
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

  if (!isset($_GET['code']) || !isset($_GET['state']) || !isset($_SESSION['naver_login']['naver_login_state_token']) ) {
    drupal_goto();
  }

  if ($_GET['state'] != $_SESSION['naver_login']['naver_login_state_token']) {
    // If invalid -> unset token and goto main page.
    unset($_SESSION['naver_login']['naver_login_state_token']);
    drupal_goto();
  }

  /**
   * Step 1. Retrieve ACCESS TOKEN using $_GET['code'] value.
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

    $curl_results_obj= json_decode($curl_results);

    if($curl_results_obj == NULL || isset($curl_results_obj->error)){
      // Error
      drupal_goto();
    }
    else{
      // Success
      $naver_login_access_user_access_token = $curl_results_obj->access_token;
    }

  /**
   * Step 2. Retrieve ACCESS TOKEN using $_GET['code'] value.
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

    if($user_profile_xml == NULL
      || !isset($user_profile_xml->result)
      || !isset($user_profile_xml->result->resultcode)
      || $user_profile_xml->result->resultcode != '00'){

      // error
      drupal_goto();
    }

  /**
    * Step 3. Processing user profile.
    */
    $user_profile_array = json_decode(json_encode($user_profile_xml), TRUE);

    $_SESSION[$_GET['state']]['user_profile'] = serialize($user_profile_array);
    
    drupal_goto('naver_login/auth/register', 
      array(
        'query'=>array(
          'state' => $_GET['state'],
        ),
      )
    );

}

/**
 * naver login service register page.
 * 
 */
function naver_login_auth_register($form, &$form_state) {

  drupal_set_title(t('Sign Up with Naver Account'));

  if (!isset($_GET['state']) 
    || !isset($_SESSION['naver_login']['naver_login_state_token'])  
    || !isset($_SESSION[$_GET['state']]['user_profile']) ) {
    drupal_goto();
  }

  if ($_GET['state'] != $_SESSION['naver_login']['naver_login_state_token']) {
    // if invalid -> unset token and goto main page.
    unset($_SESSION['naver_login']['naver_login_state_token']);
    drupal_goto();
  }

  $user_profile_array = unserialize($_SESSION[$_GET['state']]['user_profile']);

  $naver_userinfo_email = $user_profile_array['response']['email'];
  $naver_userinfo_nickname = $user_profile_array['response']['nickname'];
  $naver_userinfo_enc_id = $user_profile_array['response']['enc_id'];
  $naver_userinfo_profile_image = $user_profile_array['response']['profile_image'];
  $naver_userinfo_age = $user_profile_array['response']['age'];
  $naver_userinfo_birthday = $user_profile_array['response']['birthday'];
  $naver_userinfo_gender = $user_profile_array['response']['gender'];
    
  $drupal_uid = naver_login_get_drupal_uid_by_naver_enc_id($naver_userinfo_enc_id);
    
  if($drupal_uid){
    $exist_user = user_load($drupal_uid);

    if(!$exist_user) {
      naver_login_revoke_connection($drupal_uid);
      $drupal_uid = NULL;
      $exist_user = NULL;
    }
  }
      
    
    
  if( user_is_logged_in() && isset($_SESSION['naver_login_loggedin_user_want_connect']) ) {
    global $user;
    
    if($user->mail == $naver_userinfo_email){

      naver_login_make_connection($user->uid, $naver_userinfo_enc_id);

      $data['data']['naver_login_userinfo_email'] = $naver_userinfo_email;
      $data['data']['naver_login_userinfo_nickname'] = $naver_userinfo_nickname;
      $data['data']['naver_login_userinfo_enc_id'] = $naver_userinfo_enc_id;
      $data['data']['naver_login_userinfo_profile_image'] = $naver_userinfo_profile_image;
      $data['data']['naver_login_userinfo_age'] = $naver_userinfo_age;
      $data['data']['naver_login_userinfo_birthday'] = $naver_userinfo_birthday;
      $data['data']['naver_login_userinfo_gender'] = $naver_userinfo_gender;
      $user = user_save($user, $data);

    }
    else{
      drupal_set_message(t('Your account email is differ from Naver account. connection failed.'), 'error');
    }

    unset($_SESSION['naver_login_loggedin_user_want_connect']);
    drupal_goto('user/edit/naver_login');
    exit;
  }

  // if already connected
  if ($drupal_uid) {
  // User already registered Naver account to site, log them in     
    $form_state['uid'] = $drupal_uid;
    user_login_submit($form, $form_state);
    drupal_goto('user');//need to redirect destination
  }
  elseif (naver_login_email_already_exist($naver_userinfo_email)){
    // The user was not found in the users table, but the
    // email from Naver might already have an account.
    // Redirect user to the login page with a message..
    drupal_set_message(t('This email address is already registered to an account. Please log in to this account with the username and password provided during registration'));
    $options = array('query' => array(
      'naver_login' => 'true'
    ));
    drupal_goto('user/login', $options);
  }
  else{
    // registration
    $form = drupal_retrieve_form('user_register_form', $form_state);

    // prevent users registration if admin has blocked free registration
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

}

/**
 *  This form allows the user to manage their Naver connect settings.
 *
 *  Some options are visible only if Naver session is active.
 */
function naver_login_user_settings_form($form, $form_state, $account) {

  global $user;

  $is_admin = FALSE;

  if( in_array('administrator', $user->roles) ) {
    $is_admin = TRUE;
  }

  $form['naver_login'] = array(
    '#title' => t('Naver Login info (ADMIN VIEW)'),
    '#type' => 'fieldset',
    '#description' => t('The data received from Naver.<br />Only admin can view this info.<br />Data will remove when Naver account disconnect. (also drupal user account cancelation)<br /><br />'),
    '#access' => $is_admin,
  );

  $form['naver_login']['naver_login_userinfo_enc_id'] = array(
    '#type' => 'textfield',
    '#title' => t('User Encrypted ID'),
    '#default_value' => isset($account->data['naver_login_userinfo_enc_id']) ? $account->data['naver_login_userinfo_enc_id'] : '',
    '#disabled' => TRUE,
    '#access' => $is_admin,
  );  

  $form['naver_login']['naver_login_userinfo_email'] = array(
    '#type' => 'textfield',
    '#title' => t('User Email'),
    '#default_value' => isset($account->data['naver_login_userinfo_email']) ? $account->data['naver_login_userinfo_email'] : '',
    '#disabled' => TRUE,
    '#access' => $is_admin,
  );

  $form['naver_login']['naver_login_userinfo_nickname'] = array(
    '#type' => 'textfield',
    '#title' => t('User Nickname'),
    '#default_value' => isset($account->data['naver_login_userinfo_nickname']) ? $account->data['naver_login_userinfo_nickname'] : '',
    '#disabled' => TRUE,
    '#access' => $is_admin,
  );

  $form['naver_login']['naver_login_userinfo_profile_image'] = array(
    '#type' => 'textfield',
    '#title' => t('User Profile Image'),
    '#default_value' => isset($account->data['naver_login_userinfo_profile_image']) ? $account->data['naver_login_userinfo_profile_image'] : '',
    '#disabled' => TRUE,
    '#access' => $is_admin,
  );

  $form['naver_login']['naver_login_userinfo_age'] = array(
    '#type' => 'textfield',
    '#title' => t('User Age'),
    '#default_value' => isset($account->data['naver_login_userinfo_age']) ? $account->data['naver_login_userinfo_age'] : '',
    '#disabled' => TRUE,
    '#access' => $is_admin,
  );

  $form['naver_login']['naver_login_userinfo_birthday'] = array(
    '#type' => 'textfield',
    '#title' => t('User Birthday'),
    '#default_value' => isset($account->data['naver_login_userinfo_birthday']) ? $account->data['naver_login_userinfo_birthday'] : '',
    '#disabled' => TRUE,
    '#access' => $is_admin,
  );

  $form['naver_login']['naver_login_userinfo_gender'] = array(
    '#type' => 'textfield',
    '#title' => t('User Gender'),
    '#default_value' => isset($account->data['naver_login_userinfo_gender']) ? $account->data['naver_login_userinfo_gender'] : '',
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
    '#description' => $is_admin ? t('Admin only can do unlink function.') : '',
    //'#collapsed' => TRUE,
    //'#collapsible' => TRUE,
  );

  if(isset($account->data['naver_login_userinfo_enc_id']) && $account->data['naver_login_userinfo_enc_id'] != ''){
    $form['naver_login_connect']['unlink'] = array(
      '#type' => 'submit',
      '#value' => t('Disconnect'),
      '#validate' => array('naver_login_request_revoke'),
    );
  }
  else{
    $form['naver_login_connect']['profile'] = array(
      '#type' => 'submit',
      '#value' => t('Connect'),
      '#disabled' => $is_admin?TRUE:FALSE,
      '#validate' => array('naver_login_request_connect'),
    );
  }

  return $form;
}

/**
 *  Callback Connect
 */
function naver_login_request_connect($form, &$form_state) {
    //$form_state['rebuild'] = TRUE;
    $_SESSION['naver_login_loggedin_user_want_connect'] = TRUE;
    drupal_goto('naver_login/auth/request');
}

/**
 *  Callback Disconnect
 */
function naver_login_request_revoke($form, &$form_state) {
  $account = $form_state['values']['account'];

  naver_login_revoke_connection($account->uid);

  $data['data']['naver_login_userinfo_email'] = NULL;
  $data['data']['naver_login_userinfo_nickname'] = NULL;
  $data['data']['naver_login_userinfo_enc_id'] = NULL;
  $data['data']['naver_login_userinfo_profile_image'] = NULL;
  $data['data']['naver_login_userinfo_age'] = NULL;
  $data['data']['naver_login_userinfo_birthday'] = NULL;
  $data['data']['naver_login_userinfo_gender'] = NULL;

  user_save($account, $data);
}

/**
 * Menu callback identities
 */
function naver_login_user_identities($form_id, $account) {
  return drupal_get_form('naver_login_user_settings_form', $account);
}
