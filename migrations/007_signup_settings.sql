INSERT INTO site_settings (key, value) VALUES
    ('signups_enabled', 'true'),
    ('signup_disabled_message', 'Unfortunately, the admin has disabled new signups. Sorry!')
ON CONFLICT (key) DO NOTHING;
