export interface SafeNetwork {
    cidr: string;
    provider: string;
}

export const SAFE_NETWORKS: SafeNetwork[] = [
    // AWS IP ranges (expanded by region)
    // US East (N. Virginia) - us-east-1
    { cidr: '34.192.0.0/12', provider: 'AWS-US-EAST-1' },
    { cidr: '34.224.0.0/12', provider: 'AWS-US-EAST-1' },
    { cidr: '34.236.0.0/14', provider: 'AWS-US-EAST-1' },
    { cidr: '35.168.0.0/13', provider: 'AWS-US-EAST-1' },
    { cidr: '52.0.0.0/12', provider: 'AWS-US-EAST-1' },
    { cidr: '52.20.0.0/14', provider: 'AWS-US-EAST-1' },
    { cidr: '54.80.0.0/12', provider: 'AWS-US-EAST-1' },
    { cidr: '54.160.0.0/12', provider: 'AWS-US-EAST-1' },
    { cidr: '54.208.0.0/15', provider: 'AWS-US-EAST-1' },
    { cidr: '75.101.128.0/17', provider: 'AWS-US-EAST-1' },
    
    // US East (Ohio) - us-east-2
    { cidr: '18.188.0.0/16', provider: 'AWS-US-EAST-2' },
    { cidr: '18.216.0.0/14', provider: 'AWS-US-EAST-2' },
    { cidr: '3.128.0.0/14', provider: 'AWS-US-EAST-2' },
    { cidr: '3.16.0.0/14', provider: 'AWS-US-EAST-2' },
    
    // US West (Oregon) - us-west-2
    { cidr: '34.208.0.0/12', provider: 'AWS-US-WEST-2' },
    { cidr: '44.224.0.0/11', provider: 'AWS-US-WEST-2' },
    { cidr: '52.32.0.0/14', provider: 'AWS-US-WEST-2' },
    { cidr: '54.184.0.0/13', provider: 'AWS-US-WEST-2' },
    
    // US West (N. California) - us-west-1
    { cidr: '13.56.0.0/16', provider: 'AWS-US-WEST-1' },
    { cidr: '52.52.0.0/15', provider: 'AWS-US-WEST-1' },
    { cidr: '54.176.0.0/15', provider: 'AWS-US-WEST-1' },
    
    // EU (Ireland) - eu-west-1
    { cidr: '34.240.0.0/13', provider: 'AWS-EU-WEST-1' },
    { cidr: '52.208.0.0/13', provider: 'AWS-EU-WEST-1' },
    { cidr: '54.72.0.0/14', provider: 'AWS-EU-WEST-1' },
    { cidr: '54.216.0.0/15', provider: 'AWS-EU-WEST-1' },
    
    // EU (Frankfurt) - eu-central-1
    { cidr: '35.156.0.0/14', provider: 'AWS-EU-CENTRAL-1' },
    { cidr: '52.28.0.0/16', provider: 'AWS-EU-CENTRAL-1' },
    { cidr: '52.57.0.0/16', provider: 'AWS-EU-CENTRAL-1' },
    
    // EU (London) - eu-west-2
    { cidr: '35.176.0.0/15', provider: 'AWS-EU-WEST-2' },
    { cidr: '52.56.0.0/16', provider: 'AWS-EU-WEST-2' },
    
    // Asia Pacific (Tokyo) - ap-northeast-1
    { cidr: '13.112.0.0/14', provider: 'AWS-AP-NORTHEAST-1' },
    { cidr: '52.68.0.0/15', provider: 'AWS-AP-NORTHEAST-1' },
    { cidr: '54.64.0.0/13', provider: 'AWS-AP-NORTHEAST-1' },
    
    // Asia Pacific (Singapore) - ap-southeast-1
    { cidr: '13.228.0.0/15', provider: 'AWS-AP-SOUTHEAST-1' },
    { cidr: '52.74.0.0/16', provider: 'AWS-AP-SOUTHEAST-1' },
    { cidr: '54.169.0.0/16', provider: 'AWS-AP-SOUTHEAST-1' },
    
    // Asia Pacific (Sydney) - ap-southeast-2
    { cidr: '13.54.0.0/15', provider: 'AWS-AP-SOUTHEAST-2' },
    { cidr: '52.62.0.0/15', provider: 'AWS-AP-SOUTHEAST-2' },
    { cidr: '54.252.0.0/16', provider: 'AWS-AP-SOUTHEAST-2' },
    
    // South America (São Paulo) - sa-east-1
    { cidr: '18.228.0.0/16', provider: 'AWS-SA-EAST-1' },
    { cidr: '52.67.0.0/16', provider: 'AWS-SA-EAST-1' },
    { cidr: '54.232.0.0/16', provider: 'AWS-SA-EAST-1' },
    
    // AWS Lambda Service
    { cidr: '52.92.0.0/16', provider: 'AWS-LAMBDA' },
    { cidr: '54.144.0.0/14', provider: 'AWS-LAMBDA' },
    
    // AWS S3
    { cidr: '52.92.16.0/20', provider: 'AWS-S3' },
    { cidr: '52.216.0.0/15', provider: 'AWS-S3' },
    
    // AWS CloudFront
    { cidr: '54.192.0.0/16', provider: 'AWS-CLOUDFRONT' },
    { cidr: '204.246.164.0/22', provider: 'AWS-CLOUDFRONT' },
    { cidr: '205.251.192.0/19', provider: 'AWS-CLOUDFRONT' },
    
    // Microsoft Azure (significantly expanded)
    // Azure Global - Core Ranges
    { cidr: '13.64.0.0/11', provider: 'Azure' },
    { cidr: '13.96.0.0/13', provider: 'Azure' },
    { cidr: '13.104.0.0/14', provider: 'Azure' },
    
    // Additional Azure Global ranges - expanded to include 20.50.73.4
    { cidr: '20.0.0.0/11', provider: 'Azure' }, // Includes 20.0.0.0-20.31.255.255
    { cidr: '20.32.0.0/11', provider: 'Azure' }, // Includes 20.32.0.0-20.63.255.255 (covers 20.50.73.4)
    { cidr: '20.64.0.0/10', provider: 'Azure' },
    { cidr: '20.128.0.0/16', provider: 'Azure' },
    { cidr: '20.135.0.0/16', provider: 'Azure' },
    { cidr: '20.136.0.0/16', provider: 'Azure' },
    { cidr: '20.150.0.0/15', provider: 'Azure' },
    { cidr: '20.160.0.0/12', provider: 'Azure' },
    { cidr: '20.176.0.0/14', provider: 'Azure' },
    { cidr: '20.180.0.0/14', provider: 'Azure' },
    { cidr: '20.184.0.0/13', provider: 'Azure' },
    
    // Azure US regions
    { cidr: '52.146.0.0/15', provider: 'Azure-US' },
    { cidr: '52.148.0.0/14', provider: 'Azure-US' },
    { cidr: '52.152.0.0/13', provider: 'Azure-US' },
    { cidr: '52.160.0.0/11', provider: 'Azure-US' },
    { cidr: '52.224.0.0/11', provider: 'Azure-US' },
    { cidr: '52.149.128.0/17', provider: 'Azure-US-Virginia' },
    
    // Azure specialized services - expanded
    { cidr: '13.70.0.0/15', provider: 'Azure-Australia' },
    { cidr: '13.73.0.0/16', provider: 'Azure-Australia' },
    { cidr: '40.126.0.0/18', provider: 'Azure-CDN' },
    { cidr: '13.107.0.0/16', provider: 'Azure-Services' },
    { cidr: '51.4.0.0/15', provider: 'Azure-UK' },
    { cidr: '51.132.0.0/16', provider: 'Azure-UK' },
    
    // Azure Europe
    { cidr: '51.103.0.0/16', provider: 'Azure-Europe' },
    { cidr: '51.104.0.0/15', provider: 'Azure-Europe' },
    { cidr: '51.124.0.0/16', provider: 'Azure-Europe' },
    { cidr: '51.132.0.0/16', provider: 'Azure-Europe' },
    { cidr: '51.138.0.0/16', provider: 'Azure-Europe' },
    
    // Azure App Service environments
    { cidr: '23.96.0.0/13', provider: 'Azure-AppService' },
    { cidr: '40.64.0.0/10', provider: 'Azure-AppService' },
    { cidr: '42.159.0.0/16', provider: 'Azure-AppService-Asia' },
    
    // Google Cloud Platform (expanded by region)
    // GCP Global
    { cidr: '34.64.0.0/10', provider: 'GCP' },
    { cidr: '35.184.0.0/13', provider: 'GCP' },
    { cidr: '35.192.0.0/14', provider: 'GCP' },
    { cidr: '35.196.0.0/15', provider: 'GCP' },
    { cidr: '35.198.0.0/16', provider: 'GCP' },
    { cidr: '35.199.0.0/17', provider: 'GCP' },
    
    // Cloudflare (expanded)
    { cidr: '104.16.0.0/12', provider: 'Cloudflare' },
    { cidr: '172.64.0.0/13', provider: 'Cloudflare' },
    { cidr: '173.245.48.0/20', provider: 'Cloudflare' },
    { cidr: '108.162.192.0/18', provider: 'Cloudflare' },
    
    // Common internal networks (Private Ranges)
    { cidr: '10.0.0.0/8', provider: 'RFC1918-Private' },
    { cidr: '172.16.0.0/12', provider: 'RFC1918-Private' },
    { cidr: '192.168.0.0/16', provider: 'RFC1918-Private' },
    
    // Additional private/special use ranges
    { cidr: '127.0.0.0/8', provider: 'Loopback' },
    { cidr: '169.254.0.0/16', provider: 'Link-Local' },
    
    // AWS India Region (Mumbai) - ap-south-1
    { cidr: '13.126.0.0/15', provider: 'AWS-AP-SOUTH-1' },
    { cidr: '13.234.0.0/15', provider: 'AWS-AP-SOUTH-1' },
    { cidr: '15.206.0.0/15', provider: 'AWS-AP-SOUTH-1' },
    { cidr: '52.66.0.0/16', provider: 'AWS-AP-SOUTH-1' },
    { cidr: '3.6.0.0/15', provider: 'AWS-AP-SOUTH-1' },
    
    // AWS India Region (Hyderabad) - ap-south-2
    { cidr: '18.60.0.0/15', provider: 'AWS-AP-SOUTH-2' },
    { cidr: '65.0.0.0/15', provider: 'AWS-AP-SOUTH-2' },
    { cidr: '65.2.0.0/15', provider: 'AWS-AP-SOUTH-2' },

    // Azure India Regions - expanded
    { cidr: '52.136.0.0/16', provider: 'Azure-India-West' },
    { cidr: '20.192.0.0/15', provider: 'Azure-India-Central' },
    { cidr: '20.204.0.0/15', provider: 'Azure-India-Central' }, // Additional range
    { cidr: '52.140.0.0/15', provider: 'Azure-India-South' },
    { cidr: '104.211.0.0/18', provider: 'Azure-India' },
    { cidr: '23.100.32.0/20', provider: 'Azure-India' },
    { cidr: '20.219.0.0/16', provider: 'Azure-India' }, // Additional range
    { cidr: '20.235.0.0/16', provider: 'Azure-India' }, // Additional range
    { cidr: '40.80.0.0/15', provider: 'Azure-India' }, // Additional range

    // Google Cloud India Regions
    { cidr: '34.93.0.0/16', provider: 'GCP-Mumbai' },
    { cidr: '34.100.0.0/16', provider: 'GCP-Delhi' },
    { cidr: '34.126.0.0/16', provider: 'GCP-India' },

    // Major Indian ISPs
    // Reliance Jio
    { cidr: '49.32.0.0/12', provider: 'Jio' },  
    { cidr: '49.36.0.0/15', provider: 'Jio' },
    { cidr: '157.32.0.0/12', provider: 'Jio' },
    { cidr: '103.24.76.0/22', provider: 'Jio' },
    
    // Airtel
    { cidr: '45.112.0.0/16', provider: 'Airtel' },
    { cidr: '103.10.0.0/16', provider: 'Airtel' },
    { cidr: '125.16.0.0/16', provider: 'Airtel' },
    { cidr: '182.64.0.0/12', provider: 'Airtel' },
    { cidr: '202.62.0.0/16', provider: 'Airtel' },
    
    // BSNL/MTNL
    { cidr: '59.88.0.0/13', provider: 'BSNL' },
    { cidr: '117.192.0.0/10', provider: 'BSNL' },
    { cidr: '61.0.0.0/11', provider: 'BSNL' },
    { cidr: '14.139.0.0/16', provider: 'MTNL' },
    { cidr: '27.106.0.0/16', provider: 'MTNL' },
    
    // Vodafone Idea
    { cidr: '103.208.0.0/16', provider: 'Vodafone-Idea' },
    { cidr: '43.248.0.0/16', provider: 'Vodafone-Idea' },
    { cidr: '203.88.128.0/19', provider: 'Vodafone-Idea' },
    
    // Tata Communications
    { cidr: '180.87.0.0/16', provider: 'Tata-Communications' },
    { cidr: '203.101.64.0/18', provider: 'Tata-Communications' },
    { cidr: '203.101.0.0/18', provider: 'Tata-Communications' },
    { cidr: '45.113.0.0/16', provider: 'Tata-Communications' },

    // Major Indian Data Centers/Cloud Providers
    { cidr: '103.241.0.0/16', provider: 'NxtGen' },
    { cidr: '103.127.0.0/16', provider: 'CtrlS' },
    { cidr: '103.156.0.0/16', provider: 'Web Werks' },
    { cidr: '103.146.0.0/16', provider: 'Yotta' },
    { cidr: '103.112.0.0/16', provider: 'Netmagic' },
    { cidr: '103.251.36.0/22', provider: 'E2E Networks' },
    
    // Indian Educational/Government Networks
    { cidr: '14.139.0.0/16', provider: 'NIC-National-Informatics-Centre' },
    { cidr: '210.212.0.0/16', provider: 'ERNET-Educational-Network' },
    { cidr: '203.110.240.0/20', provider: 'STPI-Software-Technology-Parks' },
    
    // Azure Additional Global Ranges
    { cidr: '4.150.0.0/16', provider: 'Azure' },
    { cidr: '4.152.0.0/15', provider: 'Azure' },
    { cidr: '13.104.0.0/14', provider: 'Azure' },
    { cidr: '20.33.0.0/16', provider: 'Azure' },
    { cidr: '20.38.0.0/17', provider: 'Azure' },
    { cidr: '20.39.0.0/16', provider: 'Azure' },
    { cidr: '20.40.0.0/13', provider: 'Azure' },
    { cidr: '20.80.0.0/14', provider: 'Azure' },
    { cidr: '40.74.0.0/15', provider: 'Azure' },
    { cidr: '65.52.0.0/14', provider: 'Azure' },
    { cidr: '70.37.0.0/17', provider: 'Azure' },
    { cidr: '104.40.0.0/13', provider: 'Azure' },
    { cidr: '104.208.0.0/13', provider: 'Azure' },
    { cidr: '131.107.0.0/16', provider: 'Azure' },
    { cidr: '157.54.0.0/15', provider: 'Azure' },
    { cidr: '157.56.0.0/14', provider: 'Azure' },
    { cidr: '168.61.0.0/16', provider: 'Azure' },
    { cidr: '168.62.0.0/15', provider: 'Azure' },
    { cidr: '157.55.0.0/16', provider: 'Azure' },
    { cidr: '20.192.0.0/10', provider: 'Azure' },

    // Asianet Broadband (India ISP)
    { cidr: '2406:8800::/32', provider: 'Asianet-Broadband' },  // IPv6 range
    { cidr: '103.10.200.0/22', provider: 'Asianet-Broadband' }, // IPv4 range
    { cidr: '117.193.0.0/16', provider: 'Asianet-Broadband' },  // IPv4 range
    { cidr: '223.223.128.0/17', provider: 'Asianet-Broadband' }, // IPv4 range
    { cidr: '14.102.0.0/16', provider: 'Asianet-Broadband' },    // IPv4 range
    // Additional Indian ISPs
    // ACT Fibernet
    { cidr: '49.207.0.0/16', provider: 'ACT-Fibernet' },
    { cidr: '183.82.0.0/16', provider: 'ACT-Fibernet' },
    { cidr: '116.206.0.0/16', provider: 'ACT-Fibernet' },

    // Hathway
    { cidr: '106.51.0.0/17', provider: 'Hathway' },
    { cidr: '1.38.0.0/16', provider: 'Hathway' },
    { cidr: '103.230.0.0/16', provider: 'Hathway' },

    // Excitel Broadband
    { cidr: '103.204.0.0/16', provider: 'Excitel' },
    { cidr: '223.173.0.0/16', provider: 'Excitel' },

    // GTPL
    { cidr: '103.240.0.0/16', provider: 'GTPL' },
    { cidr: '122.170.0.0/16', provider: 'GTPL' },

    // Spectra
    { cidr: '119.226.0.0/16', provider: 'Spectra' },
    { cidr: '202.140.32.0/20', provider: 'Spectra' },

    // Additional Global Cloud Providers
    // DigitalOcean
    { cidr: '45.55.0.0/16', provider: 'DigitalOcean' },
    { cidr: '104.131.0.0/16', provider: 'DigitalOcean' },
    { cidr: '138.68.0.0/16', provider: 'DigitalOcean' },
    { cidr: '159.203.0.0/16', provider: 'DigitalOcean' },

    // Alibaba Cloud
    { cidr: '47.74.0.0/16', provider: 'Alibaba-Cloud' },
    { cidr: '47.89.0.0/16', provider: 'Alibaba-Cloud' },
    { cidr: '47.91.0.0/16', provider: 'Alibaba-Cloud' },
    { cidr: '47.76.0.0/16', provider: 'Alibaba-Cloud-India' },

    // Oracle Cloud
    { cidr: '129.146.0.0/16', provider: 'Oracle-Cloud' },
    { cidr: '132.145.0.0/16', provider: 'Oracle-Cloud' },
    { cidr: '134.70.0.0/16', provider: 'Oracle-Cloud' },
    { cidr: '152.67.0.0/16', provider: 'Oracle-Cloud-India' },

    //Twitter
    {cidr: '104.244.40.0/21', provider: 'Twitter'},
];