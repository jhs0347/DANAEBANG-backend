from django.db import models

class User(models.Model):
    name              = models.CharField(max_length = 45)
    email             = models.EmailField(max_length = 100, unique = True)
    password          = models.CharField(max_length = 100, null = True)
    phone_number      = models.CharField(max_length = 13, unique = True)
    image_url         = models.URLField(max_length = 2000, null = True)
    social_login_type = models.ForeignKey('SocialLoginType', on_delete = models.SET_NULL, null = True)
    social_login_id   = models.CharField(max_length = 45, null = True)
    create_at         = models.DateTimeField(auto_now_add = True)
    update_at         = models.DateTimeField(auto_now = True)
    
    class Meta:
        db_table = 'users'

class SocialLoginType(models.Model):
    name = models.CharField(max_length = 20)

    class Meta:
        db_table = 'social_login_types'

class Agent(models.Model):
    name              = models.CharField(max_length = 45)
    face_name         = models.CharField(max_length = 10)
    face_number       = models.CharField(max_length = 13)
    business_id       = models.CharField(max_length = 12)
    registration_id   = models.CharField(max_length = 16)
    address           = models.CharField(max_length = 100)
    profile_image_URL = models.URLField(max_length = 2000)
    created_at        = models.DateTimeField(auto_now_add = True)

    class Meta:
        db_table = 'agents'

class BelongedAgent(models.Model):
    name              = models.CharField(max_length = 10)
    phone_number      = models.CharField(max_length = 20)
    agent             = models.ForeignKey(Agent, on_delete = models.CASCADE)

    class Meta:
        db_table = 'belonged_agents'