# Navigate to the project directory
Set-Location -Path "D:\code\nextjs\ids\capture-service"

# Build the Go application
go build

# Run the executable with the required arguments
Start-Process -FilePath ".\capture-service.exe" -ArgumentList "-interface `"\Device\NPF_{5429026E-E352-479A-BEE6-D4D9D3F7FF51}`" -redis `"`"localhost:6379`"`""

# Keep the terminal open to view output
Pause

#Execute using .\capture-service.ps1