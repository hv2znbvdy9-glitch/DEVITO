"""Tests for configuration."""

from ava.config.settings import AppConfig, get_config, set_config


def test_app_config_creation():
    """Test creating app config."""
    config = AppConfig()
    assert config.app_name == "AVA"
    assert config.version == "0.1.0"
    assert not config.debug


def test_app_config_to_dict():
    """Test converting config to dict."""
    config = AppConfig(debug=True)
    config_dict = config.to_dict()
    assert config_dict["debug"] is True
    assert config_dict["app_name"] == "AVA"


def test_app_config_features():
    """Test config features."""
    config = AppConfig()
    assert config.features["logging"]
    assert config.features["monitoring"]
    assert config.features["validation"]


def test_get_config():
    """Test getting global config."""
    config = get_config()
    assert config is not None
    assert isinstance(config, AppConfig)


def test_set_config():
    """Test setting global config."""
    new_config = AppConfig(debug=True)
    set_config(new_config)
    assert get_config().debug is True
