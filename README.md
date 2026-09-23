# production-aws-devops-platform
Security log analytics and alerting platform deployed on AWS using FastAPI, Redis, PostgreSQL, Docker, Kubernetes, Terraform, and CI/CD.
production-aws-devops-platform/
│
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── models.py
│   └── detection.py
│
├── tests/
│
├── requirements.txt
├── .gitignore
└── README.md

main.py → FastAPI API endpoints
models.py → structure of security events
detection.py → detection rules
tests/ → automated tests
requirements.txt → Python dependencies
.gitignore → prevents unnecessary files from Git
README.md → project documentation