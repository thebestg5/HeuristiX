"""
Image Analyzer
Analyzes images for steganography and suspicious metadata.
"""

import base64
import re
from typing import Dict, List, Optional
from PIL import Image
import io


class ImageAnalyzer:
    """Analyzes images for security issues."""
    
    @staticmethod
    def analyze_image(image_data: bytes, url: str = "") -> Dict:
        """
        Analyze an image for security issues.
        
        Args:
            image_data: Raw image data
            url: The URL of the image
            
        Returns:
            Dictionary with image analysis results
        """
        result = {
            'url': url,
            'size': len(image_data),
            'format': None,
            'dimensions': None,
            'metadata': {},
            'security_issues': [],
            'warnings': []
        }
        
        try:
            # Open image
            img = Image.open(io.BytesIO(image_data))
            
            result['format'] = img.format
            result['dimensions'] = img.size
            
            # Extract metadata
            if hasattr(img, 'info'):
                result['metadata'] = img.info
            
            # Check for suspicious metadata
            ImageAnalyzer._check_metadata(result, img.info)
            
            # Check for steganography indicators
            ImageAnalyzer._check_steganography(result, image_data)
            
            # Check for suspicious image properties
            ImageAnalyzer._check_properties(result, img, image_data)
            
        except Exception as e:
            result['warnings'].append({
                'severity': 'low',
                'issue': 'Image Analysis Failed',
                'description': f'Could not analyze image: {str(e)}'
            })
        
        return result
    
    @staticmethod
    def _check_metadata(result: Dict, metadata: Dict):
        """Check image metadata for sensitive information."""
        
        # Check for EXIF data
        if metadata:
            for key, value in metadata.items():
                # Check for GPS coordinates
                if 'GPS' in key.upper():
                    result['warnings'].append({
                        'severity': 'medium',
                        'issue': 'GPS Metadata Present',
                        'description': f'Image contains GPS coordinates: {key}'
                    })
                
                # Check for camera info
                if 'Camera' in key or 'Make' in key or 'Model' in key:
                    result['warnings'].append({
                        'severity': 'low',
                        'issue': 'Camera Metadata Present',
                        'description': f'Image contains camera information: {key}'
                    })
                
                # Check for software/tool info
                if 'Software' in key or 'Tool' in key:
                    result['warnings'].append({
                        'severity': 'low',
                        'issue': 'Software Metadata Present',
                        'description': f'Image contains software information: {key}'
                    })
                
                # Check for author/creator info
                if 'Author' in key or 'Creator' in key or 'Artist' in key:
                    result['warnings'].append({
                        'severity': 'medium',
                        'issue': 'Author Metadata Present',
                        'description': f'Image contains author information: {key}'
                    })
                
                # Check for copyright info
                if 'Copyright' in key:
                    result['warnings'].append({
                        'severity': 'low',
                        'issue': 'Copyright Metadata Present',
                        'description': f'Image contains copyright information: {key}'
                    })
    
    @staticmethod
    def _check_steganography(result: Dict, image_data: bytes):
        """Check for potential steganography."""
        
        # Check for suspicious file size
        if len(image_data) > 10 * 1024 * 1024:  # > 10MB
            result['warnings'].append({
                'severity': 'medium',
                'issue': 'Large Image Size',
                'description': f'Image is unusually large ({len(image_data) / 1024 / 1024:.2f}MB)'
            })
        
        # Check for high entropy (potential hidden data)
        try:
            # Calculate byte entropy
            byte_counts = [0] * 256
            for byte in image_data:
                byte_counts[byte] += 1
            
            total = len(image_data)
            entropy = 0
            for count in byte_counts:
                if count > 0:
                    p = count / total
                    entropy -= p * (p.bit_length() - 1)  # Log2 approximation
            
            # High entropy may indicate encrypted/hidden data
            if entropy > 7.5:
                result['warnings'].append({
                    'severity': 'medium',
                    'issue': 'High Entropy Detected',
                    'description': f'Image has high entropy ({entropy:.2f}) - possible steganography'
                })
        except Exception:
            pass
    
    @staticmethod
    def _check_properties(result: Dict, img: Image, image_data: bytes):
        """Check image properties for suspicious characteristics."""
        
        # Check for 1x1 pixel images (tracking pixels)
        if img.size == (1, 1):
            result['security_issues'].append({
                'severity': 'high',
                'issue': 'Tracking Pixel Detected',
                'description': 'Image is 1x1 pixel (likely tracking pixel)'
            })
        
        # Check for very small images
        if img.size[0] < 5 or img.size[1] < 5:
            result['warnings'].append({
                'severity': 'medium',
                'issue': 'Suspiciously Small Image',
                'description': f'Image is very small: {img.size}'
            })
        
        # Check for unusual aspect ratios
        width, height = img.size
        aspect_ratio = width / height if height > 0 else 0
        if aspect_ratio > 10 or aspect_ratio < 0.1:
            result['warnings'].append({
                'severity': 'low',
                'issue': 'Unusual Aspect Ratio',
                'description': f'Image has unusual aspect ratio: {aspect_ratio:.2f}'
            })
        
        # Check for animated GIFs (can hide data in frames)
        if img.format == 'GIF' and hasattr(img, 'is_animated') and img.is_animated:
            result['warnings'].append({
                'severity': 'low',
                'issue': 'Animated GIF',
                'description': 'Animated GIF detected (data can be hidden in frames)'
            })
