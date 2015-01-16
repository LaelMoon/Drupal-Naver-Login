<?php

/**
 * @file
 * Administrative page callbacks for the module.
 */

/**
 * Administration settings form.
 *
 * @see system_settings_form()
 */
function naver_login_settings_form($form, &$form_state) {

  $form['naver_login_client_id'] = array(
    '#type' => 'textfield',
    '#title' => t('Naver Login Client ID'),
    '#default_value' => variable_get('naver_login_client_id', ''),
    '#description' => t('Visit <a href="@url" target="_blank">@url</a> to obtain Naver Login Service Credential.', array('@url' => 'https://developer.naver.com/openapi/register.nhn')),
    '#required' => TRUE,
    '#size' => 20,
  );

  $form['naver_login_client_secret'] = array(
    '#type' => 'textfield',
    '#title' => t('Naver Login Client Secret'),
    '#default_value' => variable_get('naver_login_client_secret', ''),
    '#required' => TRUE,
    '#size' => 10,
  );

  $form['naver_login_callback_uri'] = array(
    '#type' => 'textfield',
    '#title' => t('Client Callback URL'),
    '#default_value' => $GLOBALS['base_url'] . '/naver_login/auth/retrieve',
    '#description' => t('You should write this Callback URL in Your Naver Application config page.'),
    '#required' => TRUE,
    '#attributes' => array('readonly' => 'readonly'),
    '#size' => 40,
  );

  return system_settings_form($form);
}
