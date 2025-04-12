<?php
/*
Plugin Name: Ultimate Site Protect
Plugin URI: 
Description: Complete password protection solution for WordPress with customizable login page and secure authentication.
Version: 3.2
Author: Chetan Harvara
Author URI: https://chetanharvara.netlify.app
License: GPLv2 or later
Text Domain: ultimate-site-protect
*/

defined('ABSPATH') or die('Direct access not allowed');

/**
 * Ultimate Site Protect - The most reliable way to password protect your WordPress site
 * 
 * Features:
 * - Complete frontend protection with customizable login page
 * - Multiple user accounts with individual passwords
 * - Session management with configurable duration
 * - Custom CSS styling for login page
 * - Secure cookie-based authentication
 * - Easy-to-use admin interface
 * - Lightweight and fast implementation
 */

class Ultimate_Site_Protect {

    private $auth_file_path;
    private $cookie_name = 'ultra_secure_access';
    private $auth_filename = 'site-auth-gate.html';
    private $cookie_expiry_days = 30;

    public function __construct() {
        $this->auth_file_path = WP_CONTENT_DIR . '/' . $this->auth_filename;

        // Admin interface
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('admin_notices', array($this, 'show_admin_notices'));

        // Activation/deactivation
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));

        // Frontend protection
        add_action('template_redirect', array($this, 'check_access'), 1);

        // Login endpoint
        add_action('rest_api_init', array($this, 'register_rest_routes'));

        // Clean redirect parameter if present
        // add_action('init', [$this, 'clean_redirect_parameter']);
    }

    // public function clean_redirect_parameter() {
    //     if (isset($_GET['usp_redirect'])) {
    //         wp_redirect(home_url('/'));
    //         exit;
    //     }
    // }

    public function activate() {
        add_option('usp_user_pass_pairs', '{"admin":"password123"}');
        add_option('usp_cookie_expiry', $this->cookie_expiry_days);
        add_option('usp_login_title', 'Secure Login');
        add_option('usp_custom_css', '');
        add_option('usp_active', 'yes');
        add_option('usp_file_error', '');

        $this->create_auth_file();
    }

    public function deactivate() {
        if (file_exists($this->auth_file_path)) {
            @unlink($this->auth_file_path);
        }
        $this->clear_auth_cookie();
    }

    // private function clear_auth_cookie() {
    //     if (isset($_COOKIE[$this->cookie_name])) {
    //         unset($_COOKIE[$this->cookie_name]);
    //     }
    //     setcookie($this->cookie_name, '', time() - 3600, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);
    // }

    private function clear_auth_cookie() {
        setcookie($this->cookie_name, '', time() - 3600, '/', $_SERVER['HTTP_HOST'], is_ssl(), true);
        unset($_COOKIE[$this->cookie_name]);
    }

    private function create_auth_file() {
        if (!is_writable(WP_CONTENT_DIR)) {
            update_option('usp_file_error', 'WP Content directory is not writable. Please make /wp-content/ writable (755 permissions).');
            return false;
        }

        $login_url = esc_url(get_rest_url(null, 'usp/v1/login'));
        $home_url = esc_url(home_url('/'));
        $custom_css = esc_html(get_option('usp_custom_css', ''));
        
        
        try {
            $custom_css = get_option('usp_custom_css', '');
            $custom_css = wp_strip_all_tags($custom_css); // Strip any HTML tags
            $custom_css = sanitize_textarea_field($custom_css); // Sanitize CSS
        } catch (Exception $e) {
            error_log('USP: Error processing custom CSS - ' . $e->getMessage());
            $custom_css = '';
        }

        $auth_content = <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{$this->get_login_title()}</title>
    <style>
        /* Base Styles */
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, sans-serif;
            background: #f5f7fa;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            line-height: 1.6;
        }
        .login-container {
            background: #ffffff;
            padding: 2.5rem;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 420px;
            box-sizing: border-box;
        }
        .login-title {
            color: #1d2327;
            text-align: center;
            margin: 0 0 2rem 0;
            font-size: 1.75rem;
            font-weight: 500;
        }
        .login-input {
            width: 100%;
            padding: 0.875rem;
            margin-bottom: 1.25rem;
            border: 1px solid #dcdcde;
            border-radius: 4px;
            box-sizing: border-box;
            font-size: 1rem;
            transition: border-color 0.3s ease;
        }
        .login-input:focus {
            border-color: #3858e9;
            outline: none;
            box-shadow: 0 0 0 2px rgba(56, 88, 233, 0.2);
        }
        .login-button {
            width: 100%;
            padding: 0.875rem;
            background-color: #3858e9;
            color: #ffffff;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 1rem;
            font-weight: 500;
            transition: background-color 0.3s ease;
        }
        .login-button:hover {
            background-color: #1d48df;
        }
        .error-message {
            color: #d63638;
            margin: 1.25rem 0 0 0;
            padding: 0.75rem;
            background: #fcf0f1;
            border-radius: 4px;
            display: none;
            text-align: center;
            font-size: 0.9375rem;
        }
        
        /* Custom CSS */
        {$custom_css}
    </style>
</head>
<body>
    <div class="login-container">
        <h1 class="login-title">{$this->get_login_title()}</h1>
        <input type="text" id="username" class="login-input" placeholder="Username" autocomplete="username">
        <input type="password" id="password" class="login-input" placeholder="Password" autocomplete="current-password">
        <button onclick="attemptLogin()" class="login-button">Log In</button>
        <div id="error-message" class="error-message"></div>
    </div>

    <script>
    function displayError(message) {
        const errorEl = document.getElementById('error-message');
        errorEl.textContent = message;
        errorEl.style.display = 'block';
    }

    function attemptLogin() {
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value.trim();
        const errorEl = document.getElementById('error-message');
        
        errorEl.style.display = 'none';
        
        if (!username || !password) {
            errorEl.textContent = 'Please enter both username and password';
            errorEl.style.display = 'block';
            return;
        }

        fetch('{$login_url}', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        })
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.json();
        })
        .then(data => {
            if (data.success) {
                // Force full page reload to ensure cookie is recognized
                window.location.href = '{$home_url}?usp_verified=' + Date.now();
            } else {
                throw new Error(data.message || 'Invalid credentials');
            }
        })
        .catch(error => {
            errorEl.textContent = error.message;
            errorEl.style.display = 'block';
        });
    }

    document.getElementById('password').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') attemptLogin();
    });
    </script>
</body>
</html>
HTML;

        $result = file_put_contents($this->auth_file_path, $auth_content);
        
        if ($result === false) {
            update_option('usp_file_error', 'Failed to create authentication page. Please check file permissions.');
            return false;
        }
        
        return true;
    }

    public function check_access() {
        // Skip if protection is disabled
        if (get_option('usp_active') !== 'yes') {
            return;
        }

        // Skip for auth page itself
        if (strpos($_SERVER['REQUEST_URI'], $this->auth_filename) !== false) {
            return;
        }

        // Skip for WP admin and AJAX requests
        if (is_admin() || wp_doing_ajax() || wp_doing_cron()) {
            return;
        }

        // Skip verification parameter
        if (isset($_GET['usp_verified'])) {
            return;
        }

        // Skip if this is the redirect after successful login
        // if (isset($_GET['usp_redirect'])) {
        //     return;
        // }

        // Check authentication
        if (!$this->is_authenticated()) {
            if (!file_exists($this->auth_file_path)) {
                $this->create_auth_file();
            }

            if (file_exists($this->auth_file_path)) {
                wp_safe_redirect(content_url('/' . $this->auth_filename));
                exit;
            } else {
                wp_die('This site is protected. Please contact the administrator for access.');
            }
        }
    }

    private function is_authenticated() {
        if (empty($_COOKIE[$this->cookie_name])) {
            return false;
        }

        $credentials = json_decode(get_option('usp_user_pass_pairs', '{}'), true);
        foreach ($credentials as $username => $password) {
            $expected_cookie = $this->generate_cookie_value($username, $password);
            if (hash_equals($expected_cookie, $_COOKIE[$this->cookie_name])) {
                return true;
            }
        }

        $this->clear_auth_cookie();
        return false;
    }

    private function generate_cookie_value($username, $password) {
        return hash_hmac('sha256', $username . $password, AUTH_SALT);
    }

    public function add_admin_menu() {
        add_menu_page(
            'Site Protection',
            'Site Protection',
            'manage_options',
            'ultimate-site-protect',
            array($this, 'render_settings_page'),
            'dashicons-shield',
            80
        );
    }

    public function register_settings() {
        register_setting('usp_settings_group', 'usp_user_pass_pairs', [
            'type' => 'string',
            'sanitize_callback' => [$this, 'sanitize_user_pass_pairs']
        ]);

        register_setting('usp_settings_group', 'usp_cookie_expiry', [
            'type' => 'integer',
            'sanitize_callback' => 'absint'
        ]);

        register_setting('usp_settings_group', 'usp_login_title');
        register_setting('usp_settings_group', 'usp_custom_css');
        register_setting('usp_settings_group', 'usp_active');

        add_settings_section(
            'usp_main_section',
            'Protection Settings',
            [$this, 'render_settings_section'],
            'ultimate-site-protect'
        );

        add_settings_field(
            'usp_active_field',
            'Protection Status',
            [$this, 'render_active_field'],
            'ultimate-site-protect',
            'usp_main_section'
        );

        add_settings_field(
            'usp_user_pass_field',
            'Username/Password Pairs',
            [$this, 'render_user_pass_field'],
            'ultimate-site-protect',
            'usp_main_section'
        );

        add_settings_field(
            'usp_cookie_expiry_field',
            'Session Duration (days)',
            [$this, 'render_cookie_expiry_field'],
            'ultimate-site-protect',
            'usp_main_section'
        );

        add_settings_field(
            'usp_login_title_field',
            'Login Page Title',
            [$this, 'render_login_title_field'],
            'ultimate-site-protect',
            'usp_main_section'
        );

        add_settings_field(
            'usp_custom_css_field',
            'Custom CSS',
            [$this, 'render_custom_css_field'],
            'ultimate-site-protect',
            'usp_main_section'
        );
    }

    public function sanitize_user_pass_pairs($input) {
        if (empty($input)) {
            return '{}'; // Return empty JSON object if input is empty
        }

        // First try to decode the input
        $decoded = json_decode($input, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            // If not valid JSON, try to parse as plain text
            $lines = explode("\n", $input);
            $pairs = [];
            
            foreach ($lines as $line) {
                $line = trim($line);
                if (empty($line)) continue;
                
                $parts = explode(':', $line, 2);
                if (count($parts) === 2) {
                    $username = trim($parts[0]);
                    $password = trim($parts[1]);
                    if (!empty($username) && !empty($password)) {
                        $pairs[$username] = $password;
                    }
                }
            }
            
            if (!empty($pairs)) {
                return json_encode($pairs, JSON_PRETTY_PRINT);
            }
            
            add_settings_error(
                'usp_user_pass_pairs',
                'invalid_format',
                'Invalid format. Please use either JSON or username:password pairs (one per line).'
            );
            return get_option('usp_user_pass_pairs', '{}');
        }
        
        // If we got valid JSON, sanitize it
        $sanitized_pairs = [];
        foreach ($decoded as $username => $password) {
            $sanitized_pairs[sanitize_user($username, true)] = sanitize_text_field($password);
        }
        
        return json_encode($sanitized_pairs, JSON_PRETTY_PRINT);
    }

    public function sanitize_custom_css($css) {
        // Basic CSS sanitization
        $css = wp_strip_all_tags($css);
        $css = preg_replace('/<\/style>/i', '', $css);
        $css = preg_replace('/<style[^>]*>/i', '', $css);
        return $css;
    }

    public function render_user_pass_field() {
        $value = get_option('usp_user_pass_pairs', '{"admin":"password123"}');
        ?>
        <textarea name="usp_user_pass_pairs" rows="5" cols="50" class="large-text code"><?php echo esc_textarea($value); ?></textarea>
        <p class="description">
            Enter username:password pairs in either:<br>
            1) JSON format: <code>{"username1":"pass1", "username2":"pass2"}</code><br>
            2) Plain text format: <code>username1:pass1</code> (one per line)
        </p>
        <?php
    }

    public function render_custom_css_field() {
        $value = get_option('usp_custom_css', '');
        ?>
        <textarea name="usp_custom_css" rows="10" cols="50" class="large-text code"><?php echo esc_textarea($value); ?></textarea>
        <p class="description">Add custom CSS to style the login page. Example:<br>
        <code>body { background: #000; }<br>.login-container { max-width: 500px; }</code></p>
        <?php
    }



    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            
            <?php if ($error = get_option('usp_file_error')): ?>
                <div class="notice notice-error">
                    <p><?php echo esc_html($error); ?></p>
                </div>
                <?php delete_option('usp_file_error'); ?>
            <?php endif; ?>
            
            <form method="post" action="options.php">
                <?php
                settings_fields('usp_settings_group');
                do_settings_sections('ultimate-site-protect');
                submit_button('Save Settings');
                ?>
            </form>
            
            <div class="card" style="max-width: 600px; margin-top: 20px;">
                <h2>Current Status</h2>
                <p><strong>Protection:</strong> <?php echo (get_option('usp_active') === 'yes') ? '<span style="color:green;">Active</span>' : '<span style="color:red;">Inactive</span>'; ?></p>
                <p><strong>Login Page:</strong> 
                    <?php if (file_exists($this->auth_file_path)): ?>
                        <a href="<?php echo esc_url(content_url('/' . $this->auth_filename)); ?>" target="_blank">View Login Page</a>
                    <?php else: ?>
                        <span style="color:red;">Not created (check permissions)</span>
                    <?php endif; ?>
                </p>
                <p><strong>Default Credentials:</strong> admin / password123</p>
                <p><strong>Authentication File:</strong> <?php echo esc_html($this->auth_file_path); ?></p>
            </div>
        </div>
        <?php
    }

    public function render_settings_section() {
        echo '<p>Configure the protection settings for your website.</p>';
    }

    public function render_active_field() {
        $active = get_option('usp_active') === 'yes';
        ?>
        <label>
            <input type="checkbox" name="usp_active" value="yes" <?php checked($active); ?>>
            Enable site protection
        </label>
        <?php
    }

    

    public function render_cookie_expiry_field() {
        $value = get_option('usp_cookie_expiry', $this->cookie_expiry_days);
        ?>
        <input type="number" name="usp_cookie_expiry" value="<?php echo esc_attr($value); ?>" min="1" max="365" class="small-text"> days
        <?php
    }

    public function render_login_title_field() {
        $value = get_option('usp_login_title', 'Secure Login');
        ?>
        <input type="text" name="usp_login_title" value="<?php echo esc_attr($value); ?>" class="regular-text">
        <p class="description">Title displayed on the login page</p>
        <?php
    }

   

    public function show_admin_notices() {
        if ($error = get_option('usp_file_error')) {
            echo '<div class="notice notice-error"><p>' . esc_html($error) . '</p></div>';
            delete_option('usp_file_error');
        }
    }

    public function register_rest_routes() {
        register_rest_route('usp/v1', '/login', array(
            'methods' => 'POST',
            'callback' => array($this, 'handle_login_request'),
            'permission_callback' => '__return_true'
        ));
    }

    public function handle_login_request($request) {
        $params = $request->get_json_params();
        $username = sanitize_text_field($params['username'] ?? '');
        $password = sanitize_text_field($params['password'] ?? '');

        $credentials = json_decode(get_option('usp_user_pass_pairs', '{}'), true);

        if (isset($credentials[$username]) && $credentials[$username] === $password) {
            $expiry = time() + (int) get_option('usp_cookie_expiry', $this->cookie_expiry_days) * 24 * 3600;
            $cookie_value = $this->generate_cookie_value($username, $password);
            
            // Set cookie for root path and domain
            setcookie(
                $this->cookie_name,
                $cookie_value,
                $expiry,
                '/',  // Root path
                // parse_url(home_url(), PHP_URL_HOST), // Current domain
                $_SERVER['HTTP_HOST'],
                is_ssl(),
                true
            );

            return array(
                'success' => true,
                'message' => 'Login successful'
            );
        }

        return new WP_REST_Response(array(
            'success' => false,
            'message' => 'Invalid username or password'
        ), 401);
    }

    private function get_login_title() {
        return esc_html(get_option('usp_login_title', 'Secure Login'));
    }
}

new Ultimate_Site_Protect();
