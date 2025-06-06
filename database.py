import os
import datetime
from typing import Optional
from sqlmodel import Field, SQLModel, create_engine, Session, select

from dotenv import load_dotenv
load_dotenv()


class URLRecord(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    url: str
    Have_IP: int
    Have_At: int
    URL_Length: int
    URL_Depth: int
    Redirection: int
    https_Domain: int
    TinyURL: int
    Prefix_Suffix: int
    DNS_Record: int
    Web_Traffic: int
    Domain_Age: int
    Domain_End: int
    iFrame: int
    Mouse_Over: int
    Right_Click: int
    Web_Forwards: int
    Suspicious_Words: int
    Suspicious_Patterns: int
    Have_Currency: int
    GoogleIndex: int
    label: int
    feedback: Optional[str] = Field(default="correct")
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)


# sqlite_url = "sqlite:///database.db"
# engine = create_engine(sqlite_url)

DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL, echo=True)

def init_db():
    SQLModel.metadata.create_all(engine)

def save_url_record(**data):
    with Session(engine) as session:
        record = URLRecord(
            url=data['url'],
            Have_IP=data['Have_IP'],
            Have_At=data['Have_At'],
            URL_Length=data['URL_Length'],
            URL_Depth=data['URL_Depth'],
            Redirection=data['Redirection'],
            https_Domain=data['https_Domain'],
            TinyURL=data['TinyURL'],
            Prefix_Suffix=data['Prefix_Suffix'],
            DNS_Record=data['DNS_Record'],
            Web_Traffic=data['Web_Traffic'],
            Domain_Age=data['Domain_Age'],
            Domain_End=data['Domain_End'],
            iFrame=data['iFrame'],
            Mouse_Over=data['Mouse_Over'],
            Right_Click=data['Right_Click'],
            Web_Forwards=data['Web_Forwards'],
            Suspicious_Words=data['Suspicious_Words'],
            Suspicious_Patterns=data['Suspicious_Patterns'],
            Have_Currency=data['Have_Currency'],
            GoogleIndex=data['GoogleIndex'],
            label=data['label'],
            feedback=data['feedback'],
        )
        session.add(record)
        session.commit()
        session.refresh(record)

    return record
