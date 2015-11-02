# Rails Security Audit List

### 0. Security Gems
* [Brakeman](https://github.com/presidentbeef/brakeman) - A static analysis security vulnerability scanner for Ruby on Rails applications
* [Rack::Attack!!](https://github.com/kickstarter/rack-attack) - Rack middleware for blocking & throttling
* [SecureHeaders](https://github.com/twitter/secureheaders) - Security related headers all in one gem
* [Codesake-dawn](https://github.com/codesake/codesake-dawn) - a static analysis security scanner for ruby written web applications.
* [Devise](https://github.com/plataformatec/devise) - Flexible authentication solution for Rails with Warden.
* [Devise Security Extension](https://github.com/phatworx/devise_security_extension) - An enterprise security extension for devise, trying to meet industrial standard security demands for web applications.
* [Cancancan](https://github.com/CanCanCommunity/cancancan) - the authorization Gem for Ruby on Rails.
* [Pundit](https://github.com/elabs/pundit) - Minimal authorization through OO design and pure Ruby classes
* [Negative-captcha](https://github.com/subwindow/negative-captcha) - A plugin to make the process of creating a negative captcha in Rails much less painful

### 1. Unencrypted data in transit
> All sensitive data (e.g., login credentials, PII, corporate data) should be encrypted or hashed while in motion.

* Provide a secure connection over SSL.
* Ensure `Rails config.force_ssl = true`.

### 2. Cross-site scripting
> Be sure to always prevent XSS attack exploits.

* Check for any `html_safe` or `raw` in the code and consider if  the application of this will allow users to inject any malicous scripts.
* If use `html_safe` or `raw`, wrap them in Safe Buffer.
```ruby
# unsafe code
"#{first_name} #{last_name} #{link_to(phone, 'tel:'+phone)}".html_safe
# safe code
"".html_safe + "#{first_name} #{last_name} " + link_to(phone, 'tel:'+phone)
```

### 3. Injection flaws
>Injection flaws exploit vulnerabilities in web-based applications that fail to properly validate or sanitize input and/or use input securely.

* Don’t include user submitted strings in database queries! Check all model scopes and find conditions that include params or interpolated strings.
```ruby
# unsafe code 1
@projects = Project.find(:all, :conditions => "name like '%#{params[:name]}%'")

# safe code 1
@projects = Project.find(:all, :conditions => ["name like ?", "%#{params[:name]}%"] )

# unsafe code 2
name = params[:name]
@projects = Project.where("name like '%" + name + "%'");

# safe code 2
 @projects = Project.where("name like ?", "%#{params[:name]}%")
```

* Never directly use the command line methods (`%x[]`, `system()`, `exec()`, etc) with user input. 

### 4. Forceful browsing
> Authorisation checks should be performed on the server to allow or restrict access to application data and functionality.

* Implement authorization with [Cancancan](https://github.com/CanCanCommunity/cancancan) / [Pundit](https://github.com/elabs/pundit), and test to ensure that each user type can only access the correct content.
* Check the user's access rights when querying for content.
* Avoid using user-supplied data (like `params`) to determine which page to render:
```ruby
# This is bad!
def show
  render params[:view]
end
```

### 5. Parameter tampering
> Users should not be given access to parameters which may affect application functionality such as access control and business logic.

* Make non-action controller methods private.
* Avoid passing any params into `redirect_to`.
* Regular expressions - match the string's beginning and end by `\A` and `\z` instead of `^` and `$`.
* Use rails strong params.

### 6. Account & password management
> A set of protocols or systems to protect user's credentials or session tokens throughout their lifecycle.

* Password encryption methods - ensuring they are strong and safe. Use [Devise security extension](https://github.com/phatworx/devise_security_extension) to help with this. 
* Lock the account after x number of failed attempts.
* Put the admin interface to a special sub-domain.
* Implement captcha after a number of failed log-ins from a certain IP address.
* Require user to input the old password when changing their password.
* Enforce a strong password implementation.
* Avoid putting admin panel in easily guessable path.

### 7. Session & configuration management
> Session or cookie management to prevent session hijacking or session fixation

* Ensure [Devise/Warden](https://github.com/plataformatec/devise) is being used.
* Ensure that sensitive information eg: money balances, user access privilleges are not stored in session.
* Make logout button prominent in the application.
* Do not store large objects in a session. instead, store the id.
* Use ActiveRecord store or Memcached store or Redis store instead of cookie store for sessions.
* Make session expire on the server after a limited period of time (~20 minutes).
* Search the entire project for the `cookies` accessor and set all cookies as httponly and secure, eg: `cookies[:login] = {value: "user", httponly: true, secure: true}`.
* Do not store "state" in the session or a cookie, as they can be replayed / modified by attacker, otherwise, revalidate the value to ensure that it has not been modified by the user.

### 8. Unrestricted file upload
> Filter / validate uploaded attachment that may be a malicious file.

* Validate the content type and the file size of the attachment.
* place uploaded files in protected directories (or even another server).
* Filter or validate file names, eg: if a user enters "../../../etc/passwd".
* Process file upload asynchronously to avoid vulnerability of denial-of-service attacks.
* Check that the requested file is in the expected directory.

### 9. Information leakage
> Any potential to leak information for attacker to exploit.

* Ensure generic error message is being used.
  * "Invalid details" is better than "Password does not match user account".
* Ensure no sensitive credentials are stored in source code or any configuration file.
* Use `filter_parameter_logging` or `config.filter_parameters` (Rails 3) to remove sensitive data from your logs (`:password`, `:password_confirmation`, `:credit_card_number`, etc).

### 10. Request replay
> A mechanism to prevent automated submission of data. 

* Enable `protect_from_forgery, with: :exception` to protect from CSRF attack.
* Implement CAPTCHA on publicly exposed forms.
* Or use [Negative Captcha](https://github.com/subwindow/negative-captcha).

#### Resources:
* https://www.netsparker.com/blog/web-security/ruby-on-rails-security-basics/
* http://dev.housetrip.com/2014/01/14/session-store-and-security/
* http://excid3.com/blog/rails-tip-adding-password-complexity-validations-to-devise/
* https://anantasite.wordpress.com/2015/10/04/security-guidelinechecklist-for-rails-developer/
* http://daniel.fone.net.nz/blog/2013/05/20/a-better-way-to-manage-the-rails-secret-token/
* http://matthewhutchinson.net/2010/10/21/yet-another-rails-security-checklist
* https://blog.codeship.com/preproduction-checklist-for-a-rails-app/
* https://www.owasp.org/index.php/Ruby_on_Rails_Cheatsheet#Tools
* http://guides.rubyonrails.org/security.html
* http://product.reverb.com/2015/08/29/stay-safe-while-using-html_safe-in-rails/
