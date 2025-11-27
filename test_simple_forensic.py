#!/usr/bin/env python3
"""
Simple test for forensic analysis without OpenCV dependency issues
"""

from PIL import Image
import numpy as np
import os
from enhanced_forensic_analysis import EnhancedForensicAnalyzer

def create_test_image():
    """Create a simple test image using PIL"""
    # Create a simple RGB image
    img_array = np.random.randint(0, 255, (100, 100, 3), dtype=np.uint8)
    img = Image.fromarray(img_array, 'RGB')
    return img

def test_forensic_analysis():
    """Test the forensic analysis functionality"""
    print("🧪 Testing Enhanced Forensic Analysis...")
    
    try:
        # Create test image
        test_img = create_test_image()
        test_path = "test_forensic.jpg"
        test_img.save(test_path, quality=95)
        
        print("✅ Test image created")
        
        # Initialize analyzer
        analyzer = EnhancedForensicAnalyzer()
        print("✅ Analyzer initialized")
        
        # Test metadata extraction
        print("\n📊 Extracting metadata...")
        metadata = analyzer.extract_comprehensive_metadata(test_path)
        
        if "error" in metadata:
            print(f"❌ Error: {metadata['error']}")
            return False
        
        print("✅ Metadata extracted successfully")
        print(f"   Basic info: {metadata.get('basic_info', {})}")
        print(f"   Device info: {metadata.get('device_info', {})}")
        print(f"   GPS info: {metadata.get('gps_info', {})}")
        print(f"   Timestamp info: {metadata.get('timestamp_info', {})}")
        print(f"   Camera settings: {metadata.get('camera_settings', {})}")
        print(f"   Device fingerprint: {metadata.get('device_fingerprint', {})}")
        print(f"   Tampering analysis: {metadata.get('tampering_analysis', {})}")
        
        # Test evidence chain creation
        print("\n📋 Creating evidence chain...")
        evidence_chain = analyzer.create_forensic_evidence_chain(test_path, metadata)
        
        if "error" in evidence_chain:
            print(f"❌ Error: {evidence_chain['error']}")
            return False
        
        print("✅ Evidence chain created")
        print(f"   Case ID: {evidence_chain.get('case_id')}")
        print(f"   Evidence ID: {evidence_chain.get('evidence_id')}")
        print(f"   Investigation status: {evidence_chain.get('investigation_status')}")
        
        # Test report generation
        print("\n📄 Generating investigation report...")
        report = analyzer.generate_investigation_report(evidence_chain, metadata)
        
        if "failed" in report:
            print(f"❌ Error: {report}")
            return False
        
        print("✅ Investigation report generated")
        print(f"   Report length: {len(report)} characters")
        print("   Report preview:")
        print(report[:500] + "..." if len(report) > 500 else report)
        
        print("\n🎉 All forensic analysis tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        return False
    finally:
        # Cleanup
        if os.path.exists("test_forensic.jpg"):
            os.remove("test_forensic.jpg")

if __name__ == "__main__":
    success = test_forensic_analysis()
    if success:
        print("\n✅ Forensic analysis system is working correctly!")
    else:
        print("\n❌ Forensic analysis system has issues.")
        exit(1)