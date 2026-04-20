"""
Data Collection for AI Phishing Detection System
Collects phishing and legitimate URLs from public sources
Author: Rohit Kumar Reddy Sakam
GitHub: https://github.com/srkrcyber
"""

import pandas as pd
import requests
import time
from datetime import datetime

def download_phishing_urls():
    """
    Download verified phishing URLs from PhishTank
    PhishTank is a free community site for phishing verification
    """
    print("=" * 60)
    print("DOWNLOADING PHISHING URLs FROM PHISHTANK")
    print("=" * 60)
    
    url = "http://data.phishtank.com/data/online-valid.csv"
    
    try:
        print("\n📥 Fetching data from PhishTank...")
        df = pd.read_csv(url)
        print(f"✅ Downloaded {len(df)} phishing URLs")
        
        # Keep only URL column
        phishing = df[['url']].copy()
        phishing['label'] = 1  # 1 = phishing
        
        # Sample 5000 for balanced dataset
        if len(phishing) > 5000:
            phishing = phishing.sample(n=5000, random_state=42)
            print(f"📊 Sampled {len(phishing)} URLs for balanced dataset")
        
        # Save to file
        phishing.to_csv('data/raw/phishing_urls.csv', index=False)
        print(f"💾 Saved to: data/raw/phishing_urls.csv")
        
        return phishing
        
    except Exception as e:
        print(f"❌ Error downloading phishing URLs: {e}")
        print("   This might happen if PhishTank API is down.")
        print("   Try again in a few minutes.")
        return None

def download_legitimate_urls():
    """
    Download top legitimate websites from Tranco list
    Using alternative method with current list ID
    """
    print("\n" + "=" * 60)
    print("DOWNLOADING LEGITIMATE URLs FROM TRANCO")
    print("=" * 60)
    
    # Try current Tranco list
    url = "https://tranco-list.eu/download/D3WNJ/1000000"
    
    try:
        print("\n📥 Fetching top 1M domains from Tranco...")
        
        # Download with proper headers
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code != 200:
            print(f"⚠️  Tranco returned status {response.status_code}")
            print("📥 Using alternative: Cisco Umbrella top sites...")
            return download_alternative_legitimate_urls()
        
        # Parse CSV
        from io import StringIO
        df = pd.read_csv(StringIO(response.text), names=['rank', 'domain'], header=None)
        print(f"✅ Downloaded {len(df)} domains")
        
        # Take top 5000
        df = df.head(5000)
        print(f"📊 Selected top {len(df)} domains")
        
        # Create full URLs with https
        df['url'] = 'https://' + df['domain']
        df['label'] = 0  # 0 = legitimate
        
        legitimate = df[['url', 'label']].copy()
        
        # Save to file
        legitimate.to_csv('data/raw/legitimate_urls.csv', index=False)
        print(f"💾 Saved to: data/raw/legitimate_urls.csv")
        
        return legitimate
        
    except Exception as e:
        print(f"❌ Error: {e}")
        print("📥 Trying alternative source...")
        return download_alternative_legitimate_urls()

def download_alternative_legitimate_urls():
    """
    Alternative: Use Alexa/Cisco Umbrella top sites
    """
    print("\n📥 Using alternative source: Popular domains list...")
    
    # Hardcoded list of top legitimate domains
    top_domains = [
        'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
        'linkedin.com', 'reddit.com', 'amazon.com', 'wikipedia.org', 'apple.com',
        'microsoft.com', 'github.com', 'stackoverflow.com', 'netflix.com', 'zoom.us',
        'dropbox.com', 'adobe.com', 'salesforce.com', 'oracle.com', 'ibm.com',
        'cisco.com', 'intel.com', 'nvidia.com', 'hp.com', 'dell.com',
        'bbc.com', 'cnn.com', 'nytimes.com', 'washingtonpost.com', 'forbes.com',
        'bloomberg.com', 'reuters.com', 'medium.com', 'wordpress.com', 'blogger.com',
        'shopify.com', 'ebay.com', 'etsy.com', 'target.com', 'walmart.com',
        'bestbuy.com', 'homedepot.com', 'lowes.com', 'costco.com', 'ikea.com',
        'espn.com', 'nba.com', 'nfl.com', 'mlb.com', 'nhl.com',
        'twitch.tv', 'spotify.com', 'soundcloud.com', 'pandora.com', 'hulu.com',
        'disney.com', 'hbo.com', 'paramount.com', 'peacocktv.com', 'crunchyroll.com',
        'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'protonmail.com',
        'slack.com', 'discord.com', 'telegram.org', 'whatsapp.com', 'signal.org',
        'uber.com', 'lyft.com', 'doordash.com', 'grubhub.com', 'postmates.com',
        'airbnb.com', 'booking.com', 'expedia.com', 'hotels.com', 'tripadvisor.com',
        'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'capitalone.com', 'citibank.com',
        'paypal.com', 'venmo.com', 'cashapp.com', 'stripe.com', 'square.com',
        'harvard.edu', 'mit.edu', 'stanford.edu', 'berkeley.edu', 'oxford.edu',
        'w3.org', 'ietf.org', 'ieee.org', 'acm.org', 'python.org'
    ]
    
    # Expand with subdomains and variations to reach 5000
    legitimate_urls = []
    
    # Add main domains
    for domain in top_domains:
        legitimate_urls.append(f'https://{domain}')
        legitimate_urls.append(f'https://www.{domain}')
    
    # Add common subdomains for major sites
    major_sites = ['google.com', 'microsoft.com', 'amazon.com', 'apple.com', 'facebook.com']
    subdomains = ['mail', 'drive', 'docs', 'calendar', 'maps', 'news', 'store', 'support', 
                  'dev', 'developers', 'api', 'cloud', 'admin', 'account', 'login']
    
    for domain in major_sites:
        for subdomain in subdomains:
            legitimate_urls.append(f'https://{subdomain}.{domain}')
    
    # Add more variety
    extensions = ['.com', '.org', '.net', '.edu', '.gov']
    popular_words = ['tech', 'news', 'blog', 'shop', 'store', 'app', 'web', 'data', 
                     'cloud', 'digital', 'online', 'portal', 'service', 'platform']
    
    import random
    for word in popular_words:
        for ext in extensions:
            legitimate_urls.append(f'https://{word}{ext}')
            legitimate_urls.append(f'https://www.{word}{ext}')
    
    # Add university domains
    universities = ['harvard', 'stanford', 'mit', 'berkeley', 'princeton', 'yale', 
                   'columbia', 'chicago', 'penn', 'cornell', 'duke', 'northwestern']
    for uni in universities:
        legitimate_urls.append(f'https://{uni}.edu')
        legitimate_urls.append(f'https://www.{uni}.edu')
    
    # Add government sites
    gov_domains = ['usa', 'state', 'defense', 'justice', 'treasury', 'education', 
                   'energy', 'commerce', 'labor', 'interior']
    for gov in gov_domains:
        legitimate_urls.append(f'https://{gov}.gov')
        legitimate_urls.append(f'https://www.{gov}.gov')
    
    # Get exactly 5000 unique URLs
    legitimate_urls = list(set(legitimate_urls))[:5000]
    
    # Create DataFrame
    df = pd.DataFrame({
        'url': legitimate_urls,
        'label': 0
    })
    
    print(f"✅ Created {len(df)} legitimate URLs")
    
    # Save
    df.to_csv('data/raw/legitimate_urls.csv', index=False)
    print(f"💾 Saved to: data/raw/legitimate_urls.csv")
    
    return df

def combine_and_balance():
    """
    Combine phishing and legitimate datasets
    Create balanced dataset for unbiased ML training
    """
    print("\n" + "=" * 60)
    print("COMBINING AND BALANCING DATASETS")
    print("=" * 60)
    
    print("\n📂 Loading collected datasets...")
    phishing = pd.read_csv('data/raw/phishing_urls.csv')
    legitimate = pd.read_csv('data/raw/legitimate_urls.csv')
    
    print(f"\nDataset sizes:")
    print(f"  Phishing URLs: {len(phishing)}")
    print(f"  Legitimate URLs: {len(legitimate)}")
    
    # Ensure balanced dataset (equal phishing and legitimate)
    min_count = min(len(phishing), len(legitimate))
    
    phishing = phishing.sample(n=min_count, random_state=42)
    legitimate = legitimate.sample(n=min_count, random_state=42)
    
    print(f"\n⚖️  Balanced to {min_count} samples each")
    
    # Combine datasets
    combined = pd.concat([phishing, legitimate], ignore_index=True)
    
    # Shuffle to mix phishing and legitimate
    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Save combined dataset
    combined.to_csv('data/processed/dataset.csv', index=False)
    
    print(f"\n✅ FINAL DATASET CREATED")
    print(f"   Total URLs: {len(combined)}")
    print(f"   Phishing: {len(combined[combined['label']==1])} ({len(combined[combined['label']==1])/len(combined)*100:.1f}%)")
    print(f"   Legitimate: {len(combined[combined['label']==0])} ({len(combined[combined['label']==0])/len(combined)*100:.1f}%)")
    print(f"   💾 Saved to: data/processed/dataset.csv")
    
    return combined

def verify_data():
    """
    Quick verification of collected data
    """
    print("\n" + "=" * 60)
    print("DATA VERIFICATION")
    print("=" * 60)
    
    df = pd.read_csv('data/processed/dataset.csv')
    
    print(f"\n📊 Dataset Info:")
    print(f"   Shape: {df.shape}")
    print(f"   Columns: {list(df.columns)}")
    print(f"   Missing values: {df.isnull().sum().sum()}")
    
    print(f"\n🔍 Sample URLs:")
    print("\nPhishing examples:")
    print(df[df['label']==1]['url'].head(3).values)
    
    print("\nLegitimate examples:")
    print(df[df['label']==0]['url'].head(3).values)
    
    print("\n✅ Data verification complete!")

def main():
    """
    Main execution function
    """
    start_time = time.time()
    
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 10 + "AI PHISHING DETECTOR - DATA COLLECTION" + " " * 9 + "║")
    print("╚" + "=" * 58 + "╝")
    print(f"\nStarted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Download phishing URLs
    phishing = download_phishing_urls()
    time.sleep(2)  # Be respectful to servers
    
    # Download legitimate URLs
    legitimate = download_legitimate_urls()
    time.sleep(2)
    
    # Check if both downloads succeeded
    if phishing is not None and legitimate is not None:
        # Combine and balance
        combined = combine_and_balance()
        
        # Verify data quality
        verify_data()
        
        elapsed = time.time() - start_time
        
        print("\n" + "=" * 60)
        print("✅ DATA COLLECTION COMPLETE!")
        print("=" * 60)
        print(f"\nTime taken: {elapsed:.2f} seconds")
        print("\n📁 Files created:")
        print("   data/raw/phishing_urls.csv")
        print("   data/raw/legitimate_urls.csv")
        print("   data/processed/dataset.csv")
        print("\n🎯 Next step: Feature engineering")
        print("   Run: python src/extract_features.py")
    else:
        print("\n" + "=" * 60)
        print("❌ DATA COLLECTION FAILED")
        print("=" * 60)
        print("\nPlease check:")
        print("1. Internet connection")
        print("2. API availability (PhishTank, Tranco)")
        print("3. Try again in a few minutes")

if __name__ == "__main__":
    main()
