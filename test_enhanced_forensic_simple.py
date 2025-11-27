#!/usr/bin/env python3
"""
Test script for EnhancedForensicAnalyzerSimple
Tests the forensic analysis functionality without OpenCV dependencies
"""

import sys
import os
from enhanced_forensic_analysis_simple import EnhancedForensicAnalyzerSimple

def test_forensic_analyzer():
    """Test the enhanced forensic analyzer with sample data"""
    print("🕵️ Testing Enhanced Forensic Analyzer Simple")
    print("=" * 60)
    
    # Initialize analyzer
    analyzer = EnhancedForensicAnalyzerSimple()
    print("✅ Analyzer initialized successfully")
    
    # Test with a sample image (if available)
    test_image = "test_image.jpg"  # You can change this to any image path
    
    if os.path.exists(test_image):
        print(f"🖼️ Testing with image: {test_image}")
        
        try:
            # Extract comprehensive metadata
            print("📊 Extracting comprehensive metadata...")
            metadata = analyzer.extract_comprehensive_metadata(test_image)
            
            if 'error' in metadata:
                print(f"❌ Error extracting metadata: {metadata['error']}")
                return False
            
            print("✅ Metadata extracted successfully")
            
            # Display key findings
            print("\n🔍 KEY FORENSIC FINDINGS:")
            print("-" * 40)
            
            # Device information
            device_info = metadata.get('device_info', {})
            print(f"📱 Device: {device_info.get('manufacturer', 'Unknown')} {device_info.get('model', 'Unknown')}")
            
            # GPS information
            gps_info = metadata.get('gps_info', {})
            if gps_info.get('coordinates'):
                print(f"📍 GPS Location: {gps_info.get('coordinates', 'Unknown')}")
                location_name = gps_info.get('location_name', {})
                if location_name and 'full_address' in location_name:
                    print(f"📍 Location Name: {location_name['full_address']}")
            else:
                print("📍 No GPS data found")
            
            # Timestamp information
            timestamp_info = metadata.get('timestamp_info', {})
            if timestamp_info.get('creation_datetime'):
                print(f"⏰ Creation Time: {timestamp_info['creation_datetime']}")
            
            # Tampering analysis
            tampering_analysis = metadata.get('tampering_analysis', {})
            tampering_score = tampering_analysis.get('metadata_tampering_score', 0)
            tampering_likelihood = tampering_analysis.get('tampering_likelihood', 'Unknown')
            
            print(f"🚨 Tampering Score: {tampering_score}/10")
            print(f"🚨 Tampering Assessment: {tampering_likelihood}")
            
            # Device fingerprint
            device_fingerprint = metadata.get('device_fingerprint', {})
            if device_fingerprint.get('hash'):
                print(f"🔐 Device Fingerprint: {device_fingerprint['hash'][:16]}...")
                print(f"🔐 Device Type: {device_fingerprint.get('device_type', 'Unknown')}")
            
            # Create evidence chain
            print("\n🔗 Creating forensic evidence chain...")
            evidence_chain = analyzer.create_forensic_evidence_chain(test_image, metadata)
            
            if 'error' not in evidence_chain:
                print(f"✅ Evidence chain created: {evidence_chain.get('case_id', 'Unknown')}")
                print(f"✅ Evidence ID: {evidence_chain.get('evidence_id', 'Unknown')}")
            
            # Generate investigation report
            print("\n📋 Generating investigation report...")
            report = analyzer.generate_investigation_report(evidence_chain, metadata)
            
            # Save report to file
            report_file = f"forensic_report_{evidence_chain.get('case_id', 'unknown')}.txt"
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report)
            
            print(f"✅ Investigation report saved to: {report_file}")
            
            # Display report summary
            print("\n📋 INVESTIGATION REPORT SUMMARY:")
            print("-" * 40)
            lines = report.split('\n')
            for line in lines[:20]:  # Show first 20 lines
                print(line)
            if len(lines) > 20:
                print(f"... and {len(lines) - 20} more lines")
            
            return True
            
        except Exception as e:
            print(f"❌ Error during forensic analysis: {str(e)}")
            return False
    else:
        print(f"⚠️ Test image not found: {test_image}")
        print("💡 Please provide a valid image path to test the forensic analyzer")
        
        # Test individual methods with mock data
        print("\n🔧 Testing individual methods with mock data...")
        
        # Test color depth calculation
        print("Testing _get_color_depth method...")
        test_cases = [
            ('RGB', 24),
            ('RGBA', 32),
            ('L', 8),
            ('P', 8),
            ('1', 1),
            ('CMYK', 32)
        ]
        
        for mode, expected in test_cases:
            result = analyzer._get_color_depth(mode)
            status = "✅" if result == expected else "❌"
            print(f"  {status} Mode '{mode}': expected {expected}, got {result}")
        
        # Test GPS coordinate conversion
        print("\nTesting _convert_gps_coordinates method...")
        test_coords = (
            ((40, 1), (30, 1), (0, 1)),  # 40°30'0"N
            'N'
        )
        result = analyzer._convert_gps_coordinates(test_coords[0], test_coords[1])
        print(f"  GPS Coordinates: {test_coords[0]} {test_coords[1]} = {result}°")
        
        # Test device fingerprint generation
        print("\nTesting _generate_device_fingerprint method...")
        mock_metadata = {
            'device_info': {
                'manufacturer': 'Apple',
                'model': 'iPhone 13 Pro',
                'lens_manufacturer': 'Apple',
                'lens_model': 'iPhone 13 Pro back triple camera'
            },
            'camera_settings': {
                'color_space': 'sRGB'
            }
        }
        fingerprint = analyzer._generate_device_fingerprint(mock_metadata)
        print(f"  Device Fingerprint: {fingerprint.get('hash', 'Unknown')}")
        print(f"  Device Type: {fingerprint.get('device_type', 'Unknown')}")
        print(f"  Likely Smartphone: {fingerprint.get('likely_smartphone', False)}")
        
        return True

def main():
    """Main test function"""
    print("Enhanced Forensic Analyzer Simple - Test Suite")
    print("=" * 60)
    
    success = test_forensic_analyzer()
    
    if success:
        print("\n✅ All tests completed successfully!")
        print("🎉 Enhanced Forensic Analyzer Simple is ready for use!")
    else:
        print("\n❌ Some tests failed. Please check the error messages above.")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())