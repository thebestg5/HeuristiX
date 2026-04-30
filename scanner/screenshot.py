"""
Screenshot Capture Module
Captures screenshots of websites during scanning for visual inspection.
"""

import os
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from PIL import Image
from typing import Optional


class ScreenshotCapture:
    """Captures screenshots of websites for visual analysis."""
    
    def __init__(self, headless: bool = True):
        """Initialize screenshot capture with Selenium WebDriver."""
        self.driver = None
        self.headless = headless
        self._init_driver()
    
    def _init_driver(self):
        """Initialize Chrome WebDriver with options."""
        chrome_options = Options()
        if self.headless:
            chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--window-size=1920,1080')
        chrome_options.add_argument('--disable-extensions')
        chrome_options.add_argument('--disable-plugins')
        
        try:
            self.driver = webdriver.Chrome(options=chrome_options)
        except Exception as e:
            print(f"Failed to initialize WebDriver: {e}")
            self.driver = None
    
    def capture(self, url: str, output_path: str, wait_time: int = 3) -> bool:
        """
        Capture a screenshot of the given URL.
        
        Args:
            url: The URL to capture
            output_path: Path to save the screenshot
            wait_time: Seconds to wait for page load
            
        Returns:
            True if successful, False otherwise
        """
        if not self.driver:
            print("WebDriver not initialized")
            return False
        
        try:
            self.driver.get(url)
            time.sleep(wait_time)
            
            # Ensure output directory exists
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            self.driver.save_screenshot(output_path)
            
            # Optimize image size
            try:
                img = Image.open(output_path)
                img.thumbnail((1920, 1080))
                img.save(output_path, 'PNG', optimize=True)
            except Exception:
                pass
            
            return True
        except Exception as e:
            print(f"Failed to capture screenshot: {e}")
            return False
    
    def capture_full_page(self, url: str, output_path: str, wait_time: int = 3) -> bool:
        """
        Capture a full-page screenshot with scrolling.
        
        Args:
            url: The URL to capture
            output_path: Path to save the screenshot
            wait_time: Seconds to wait for page load
            
        Returns:
            True if successful, False otherwise
        """
        if not self.driver:
            print("WebDriver not initialized")
            return False
        
        try:
            self.driver.get(url)
            time.sleep(wait_time)
            
            # Get total page height
            total_height = self.driver.execute_script("return document.body.scrollHeight")
            
            # Set window size to capture full page
            self.driver.set_window_size(1920, total_height)
            time.sleep(1)
            
            # Ensure output directory exists
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            self.driver.save_screenshot(output_path)
            
            # Reset window size
            self.driver.set_window_size(1920, 1080)
            
            return True
        except Exception as e:
            print(f"Failed to capture full page screenshot: {e}")
            return False
    
    def close(self):
        """Close the WebDriver."""
        if self.driver:
            self.driver.quit()
            self.driver = None
    
    def __del__(self):
        """Cleanup on deletion."""
        self.close()
