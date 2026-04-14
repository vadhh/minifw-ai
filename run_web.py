import os
from dotenv import load_dotenv

if __name__ == "__main__":
    load_dotenv()
    import uvicorn
    uvicorn.run("app.web.app:app", host="0.0.0.0", port=8443, reload=True)
