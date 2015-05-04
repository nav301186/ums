class User < ActiveRecord::Base
  TEMP_EMAIL_PREFIX = 'change@me'
  TEMP_EMAIL_REGEX = /\Achange@me/

  attr_accessor :signin
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable, :confirmable,
         :recoverable, :rememberable, :trackable, :validatable, :omniauthable

  validates :username, :uniqueness => {:case_sensitive => false}
  validates_format_of :email, :without => TEMP_EMAIL_REGEX, on: :update

  def self.find_for_oauth(auth, signed_in_resource = nil)
  	identity = Identity.find_for_oauth(auth)

#it is possible that the identity.user is nil
#in that case we will have to check of user has a value or not
  	user = signed_in_resource ? signed_in_resource : identity.user

#there is no user corresponding to the identity that we got
#first try to find the user by email.
#we will create new user only if we cant find it
#this assumes that for user our primary key is email id
  	if user.nil?
  		email_is_verified = auth.info.email && (auth.info.verified || auth.email.verified_email)
  		email = auth.info.email if email_is_verified
  		user = User.where(:email => email).first if email

  #case where user do not exit at all; need to creat one
  	    if user.nil?
	  		user = User.new(
	            name: auth.extra.raw_info.name,
	            email: email ? email : "#{TEMP_EMAIL_PREFIX}-#{auth.uid}-#{auth.provider}.com",
	            password: Devise.friendly_token[0,20]
	  			)
	  		user.skip_confirmation!
	  		user.save!
  		end
  	end

  		#now is the time that we relate identity and the user
  		if identity.user != user
  			identity.user = user
  			identity.save
  		end
  		user
   end


  def email_verified?
  		self.email && self.email !~ TEMP_EMAIL_REGEX
  	end

  protected
  def self.find_first_by_auth_conditions(warden_conditions)
    if warden_conditions[:signin].blank? 
      super warden_conditions
    else
      conditions = warden_conditions.dup.permit!
      where(conditions).where(["lower(username) = :value OR lower(email) = :value",
       {:value => signin.downcase}])
      .first
    end
  end

end
