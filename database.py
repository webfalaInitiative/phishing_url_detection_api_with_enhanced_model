from sqlmodel import Field, SQLModel, create_engine, Session, select
from typing import Optional
import datetime

class URLRecord(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    url: str
    using_ip: int
    long_url: int
    short_url: int
    symbol: int
    redirecting: int
    prefix_suffix: int
    subdomains: int
    https: int
    domain_reg_len: int
    favicon: int
    non_std_port: int
    https_domain_url: int
    request_url: int
    anchor_url: int
    links_in_script_tags: int
    server_form_handler: int
    info_email: int
    abnormal_url: int
    website_forwarding: int
    status_bar_cust: int
    disable_right_click: int
    using_popup_window: int
    iframe_redirection: int
    age_of_domain: int
    dns_recording: int
    website_traffic: int
    pagerank: int
    google_index: int
    links_pointing_to_page: int
    stats_report: int
    label: int
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)

sqlite_url = "sqlite:///database.db"
engine = create_engine(sqlite_url)

def init_db():
    SQLModel.metadata.create_all(engine)

def save_url_record(**data):
    with Session(engine) as session:
        record = URLRecord(
            url=data['url'],
            using_ip=data['using_ip'],
            long_url=data['long_url'],
            short_url=data['short_url'],
            symbol=data['symbol'],
            redirecting=data['redirecting'],
            prefix_suffix=data['prefix_suffix'],
            subdomains=data['subdomains'],
            https=data['https'],
            domain_reg_len=data['domain_reg_len'],
            favicon=data['favicon'],
            non_std_port=data['non_std_port'],
            https_domain_url=data['https_domain_url'],
            request_url=data['request_url'],
            anchor_url=data['anchor_url'],
            links_in_script_tags=data['links_in_script_tags'],
            server_form_handler=data['server_form_handler'],
            info_email=data['info_email'],
            abnormal_url=data['abnormal_url'],
            website_forwarding=data['website_forwarding'],
            status_bar_cust=data['status_bar_cust'],
            disable_right_click=data['disable_right_click'],
            using_popup_window=data['using_popup_window'],
            iframe_redirection=data['iframe_redirection'],
            age_of_domain=data['age_of_domain'],
            dns_recording=data['dns_recording'],
            website_traffic=data['website_traffic'],
            pagerank=data['pagerank'],
            google_index=data['google_index'],
            links_pointing_to_page=data['links_pointing_to_page'],
            stats_report=data['stats_report'],
            label=data['label'],
        )
        session.add(record)
        session.commit()
