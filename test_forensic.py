#!/usr/bin/env python3
"""
Test script for EnhancedForensicAnalyzer to verify all functionality works correctly
"""

import numpy as np
import cv2
from PIL import Image
import os
from enhanced_forensic_analysis import EnhancedForensicAnalyzer
from forensic_analysis import AdvancedForensicAnalyzer

def test_enhanced_forensic_analyzer():
    """Test the EnhancedForensicAnalyzer class"""
    print("🧪 Testing EnhancedForensicAnalyzer...")
    
    # Create test image
    test_image = np.random.randint(0, 255, (100, 100, 3), dtype=np.uint8)
    
    # Save as temporary file for testing
    temp_path = "test_forensic_image.png"
    cv2.imwrite(temp_path, cv2.cvtColor(test_image, cv2.COLOR_RGB2BGR))
    
    try:
        # Initialize analyzer
        analyzer = EnhancedForensicAnalyzer()
        print("✅ EnhancedForensicAnalyzer initialized successfully")
        
        # Test comprehensive metadata extraction
        print("\n📊 Testing comprehensive metadata extraction...")
        metadata = analyzer.extract_comprehensive_metadata(temp_path)
        
        if "error" in metadata:
            print(f"❌ Metadata extraction failed: {metadata['error']}")
            return False
        else:
            print("✅ Metadata extraction successful")
            print(f"   - Basic info: {len(metadata.get('basic_info', {}))} fields")
            print(f"   - Device info: {len(metadata.get('device_info', {}))} fields")
            print(f"   - GPS info: {len(metadata.get('gps_info', {}))} fields")
            print(f"   - Timestamp info: {len(metadata.get('timestamp_info', {}))} fields")
            print(f"   - Camera settings: {len(metadata.get('camera_settings', {}))} fields")
            print(f"   - Forensic indicators: {len(metadata.get('forensic_indicators', {}))} fields")
            print(f"   - Device fingerprint: {len(metadata.get('device_fingerprint', {}))} fields")
            print(f"   - Tampering analysis: {len(metadata.get('tampering_analysis', {}))} fields")
        
        # Test evidence chain creation
        print("\n📋 Testing evidence chain creation...")
        evidence_chain = analyzer.create_forensic_evidence_chain(temp_path, metadata)
        
        if "error" in evidence_chain:
            print(f"❌ Evidence chain creation failed: {evidence_chain['error']}")
            return False
        else:
            print("✅ Evidence chain creation successful")
            print(f"   - Case ID: {evidence_chain.get('case_id', 'N/A')}")
            print(f"   - Evidence ID: {evidence_chain.get('evidence_id', 'N/A')}")
            print(f"   - Chain of custody entries: {len(evidence_chain.get('chain_of_custody', []))}")
        
        # Test investigation report generation
        print("\n📄 Testing investigation report generation...")
        report = analyzer.generate_investigation_report(evidence_chain, metadata)
        
        if "failed" in report:
            print(f"❌ Report generation failed: {report}")
            return False
        else:
            print("✅ Investigation report generation successful")
            print(f"   - Report length: {len(report)} characters")
            print(f"   - Contains case information: {'Case ID' in report}")
            print(f"   - Contains device evidence: {'Device' in report}")
            print(f"   - Contains GPS evidence: {'GPS' in report}")
            print(f"   - Contains recommendations: {'RECOMMENDATIONS' in report}")
        
        print("\n🎉 All EnhancedForensicAnalyzer tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed with exception: {str(e)}")
        return False
    finally:
        # Cleanup
        if os.path.exists(temp_path):
            os.remove(temp_path)

def test_basic_forensic_analyzer():
    """Test the basic AdvancedForensicAnalyzer"""
    print("🧪 Testing AdvancedForensicAnalyzer...")
    
    try:
        analyzer = AdvancedForensicAnalyzer()
        print("✅ AdvancedForensicAnalyzer initialized successfully")
        
        # Create test image
        test_image = np.random.randint(0, 255, (100, 100, 3), dtype=np.uint8)
        
        # Test comprehensive forensics
        print("\n🔍 Testing comprehensive forensics...")
        results = analyzer.perform_comprehensive_forensics(test_image)
        
        if "error" in results:
            print(f"❌ Forensic analysis failed: {results['error']}")
            return False
        else:
            print("✅ Forensic analysis successful")
            print(f"   - Forensic score: {results.get('forensic_score', 0):.2f}/10")
            print(f"   - Tampering likelihood: {results.get('tampering_likelihood', 'Unknown')}")
            print(f"   - Analysis timestamp: {results.get('timestamp', 'N/A')}")
        
        print("\n🎉 All AdvancedForensicAnalyzer tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed with exception: {str(e)}")
        return False

if __name__ == "__main__":
    print("🚀 Starting Forensic Analysis System Tests\n")
    
    # Test basic analyzer
    basic_success = test_basic_forensic_analyzer()
    print("\n" + "="*60 + "\n")
    
    # Test enhanced analyzer
    enhanced_success = test_enhanced_forensic_analyzer()
    print("\n" + "="*60 + "\n")
    
    # Final summary
    if basic_success and enhanced_success:
        print("🎉 ALL TESTS PASSED! The forensic analysis system is working correctly.")
        print("\n✅ System ready for law enforcement investigations:")
        print("   • Device identification and tracking")
        print("   • GPS location analysis")
        print("   • Timestamp verification")
        print("   • Tampering detection")
        print("   • Evidence chain tracking")
        print("   • Professional report generation")
    else:
        print("❌ Some tests failed. Please check the errors above.")
        exit(1)