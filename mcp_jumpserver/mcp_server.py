import os
import httpx
import logging
import re
import asyncio
from datetime import datetime, timedelta
from typing import Annotated, List, Optional, Dict, Any
from functools import wraps
from dotenv import load_dotenv
from fastmcp import FastMCP
from logging.handlers import RotatingFileHandler
from pydantic import (
    BaseModel, Field, PositiveInt, constr, AfterValidator, 
    ValidationError, field_validator
)

"""
JumpServer MCP Server 代理服务
"""

# 加载 .env 配置文件
load_dotenv()

# ====== 1. 全局配置（与文档章节2/3/10/14对齐）======
CONFIG = {
    "JUMPSERVER_API_BASE_URL": os.getenv("JUMPSERVER_API_BASE_URL", "https://js-internal.fit2cloud.cn/api/v1"),
    "DEFAULT_ORG_ID": os.getenv("DEFAULT_ORG_ID", "413da40d-b16a-4ee2-b658-10b16c7c87e7"),  # 文档10.1/14.1默认组织ID
    "ADMIN_USERNAME": os.getenv("ADMIN_USERNAME", "admin"),
    "ADMIN_PASSWORD": os.getenv("ADMIN_PASSWORD", "P@ssw0rd"),
    "TOKEN_EXPIRE_HOURS": int(os.getenv("TOKEN_EXPIRE_HOURS", "24")),  # 文档3.2 Token有效期
    "TASK_TIMEOUT": int(os.getenv("TASK_TIMEOUT", "30")),  # API超时（秒）
    "LOG_DIR": os.getenv("LOG_DIR", "./log/mcp_server"),
    "LOG_MAX_SIZE": int(os.getenv("LOG_MAX_SIZE", "100")),  # 单位：MB
    "LOG_BACKUP_COUNT": int(os.getenv("LOG_BACKUP_COUNT", "10")),
    "TASK_LOG_DIR":os.getenv("LOG_DIR", "/data/jumpserver/core/data/celery")
}

# ====== 2. 日志配置======
os.makedirs(CONFIG["LOG_DIR"], exist_ok=True)
log_file = os.path.join(CONFIG["LOG_DIR"], "mcp_server.log")
log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
date_format = "%Y-%m-%d %H:%M:%S"
formatter = logging.Formatter(log_format, datefmt=date_format)

logger = logging.getLogger("mcp_server")
logger.setLevel(logging.DEBUG)
logger.propagate = False

# 控制台日志
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# 文件日志
file_handler = RotatingFileHandler(
    log_file,
    maxBytes=CONFIG["LOG_MAX_SIZE"] * 1024 * 1024,
    backupCount=CONFIG["LOG_BACKUP_COUNT"],
    encoding="utf-8"
)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

logger.info("日志系统初始化完成，路径：%s", CONFIG["LOG_DIR"])

# ====== 3. 公共工具初始化======
client = httpx.AsyncClient(
    timeout=CONFIG["TASK_TIMEOUT"],
    limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
    headers={"User-Agent": "JumpServer-MCP-Client/1.0"}
)

_token_cache = {
    "token": None,
    "keyword": None,
    "expire_at": 0  # 过期时间戳（秒）
}

mcp = FastMCP("JumpServer MCP Server")

# ====== 4. 公共函数======
async def get_token_and_headers(username: str = None, password: str = None) -> tuple:
    """公共函数：获取Token及请求头（文档3.2节）"""
    global _token_cache
    current_time = datetime.now().timestamp()

    if _token_cache["token"] and _token_cache["expire_at"] > current_time:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-JMS-ORG": CONFIG["DEFAULT_ORG_ID"],
            "Authorization": f"{_token_cache['keyword']} {_token_cache['token']}"
        }
        return _token_cache["token"], headers

    auth_username = username or CONFIG["ADMIN_USERNAME"]
    auth_password = password or CONFIG["ADMIN_PASSWORD"]
    auth_url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/authentication/auth/"
    
    try:
        response = await client.post(auth_url, json={"username": auth_username, "password": auth_password})
        response.raise_for_status()
        auth_data = response.json()

        _token_cache.update({
            "token": auth_data["token"],
            "keyword": auth_data["keyword"],
            "expire_at": current_time + CONFIG["TOKEN_EXPIRE_HOURS"] * 3600
        })

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-JMS-ORG": CONFIG["DEFAULT_ORG_ID"],
            "Authorization": f"{auth_data['keyword']} {auth_data['token']}"
        }
        return auth_data["token"], headers
    except Exception as e:
        logger.error(f"Token获取失败：{str(e)}", exc_info=True)
        raise Exception(f"Authentication failed: {str(e)}")


async def send_api_request(method: str, url: str, **kwargs) -> dict:
    """公共函数：发送API请求（所有章节通用）"""
    if "headers" not in kwargs:
        _, headers = await get_token_and_headers()
        kwargs["headers"] = headers
    else:
        kwargs["headers"]["X-JMS-ORG"] = CONFIG["DEFAULT_ORG_ID"]
        if "Authorization" not in kwargs["headers"]:
            _, headers = await get_token_and_headers()
            kwargs["headers"]["Authorization"] = headers["Authorization"]

    try:
        logger.debug(f"API请求: method={method}, url={url}, params={kwargs.get('params')}, json={kwargs.get('json')}, X-JMS-ORG={kwargs['headers']['X-JMS-ORG']}")
        response = await client.request(method=method, url=url, timeout=CONFIG["TASK_TIMEOUT"], **kwargs)
        response.raise_for_status()
        if response.status_code == 204:
            return {"status": "ok"}
        return response.json()
    except Exception as e:
        error_msg = f"API请求失败 [{method} {url}]: {str(e)}"
        logger.error(error_msg, exc_info=True)
        raise Exception(error_msg)


def validate_params(model):
    """公共装饰器：参数校验（所有章节通用）"""
    def decorator(func):
        @wraps(func)
        async def wrapper(params):
            try:
                if isinstance(params, dict):
                    return await func(model(** params))
                elif isinstance(params, model):
                    return await func(params)
                else:
                    return {"code": -32602, "message": "参数需为JSON对象", "data": {}}
            except ValidationError as e:
                errors = [{"field": ".".join(str(loc) for loc in err["loc"]), "message": err["msg"]} for err in e.errors()]
                return {"code": -32602, "message": "参数错误", "data": {"details": errors}}
        return wrapper
    return decorator


def validate_uuid(v: str) -> str:
    """公共校验器：UUID格式（文档所有ID要求）"""
    if not re.fullmatch(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', v, re.IGNORECASE):
        raise ValueError(f"无效UUID格式：{v}，需符合 xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
    return v


def validate_ipv4(v: str) -> str:
    """公共校验器：IPv4地址（文档10.3.2节）"""
    if not re.fullmatch(r'^(?:\d{1,3}\.){3}\d{1,3}$', v):
        raise ValueError(f"无效IPv4地址：{v}，需符合格式（如192.168.1.1）")
    return v

# ====== 5. 章节2：用户模块（文档第2章）======
class ListUsersParams(BaseModel):
    limit: PositiveInt = Field(default=20, le=100)
    offset: int = Field(default=0, ge=0)
    id: Optional[Annotated[str, AfterValidator(validate_uuid)]] = None
    name: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    source: Optional[str] = None
    is_active: Optional[bool] = None


class CreateUserParams(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    name: str = Field(..., min_length=1, max_length=100)
    email: str = Field(...)
    password: str = Field(..., min_length=6)
    system_roles: List[Dict[str, str]] = Field(...)
    org_roles: List[Dict[str, str]] = Field(...)
    wechat: Optional[str] = None
    phone: Optional[str] = None
    groups: Optional[List[Dict[str, str]]] = None


@mcp.tool()
@validate_params(ListUsersParams)
async def list_users(params: ListUsersParams) -> dict:
    """
    功能说明：分页查询用户列表（文档2.1节“查询用户”）
    接口路径：GET /api/v1/users/users/
    参数说明：
      - limit: 每页条数（默认20，最大100）
      - offset: 偏移量（默认0）
      - id: 用户ID（精确匹配，需通过本方法返回值获取）
      - name: 姓名（模糊匹配）
      - username: 用户名（模糊匹配）
      - email: 邮箱（模糊匹配）
      - source: 用户来源（local/ldap等）
      - is_active: 是否激活（true/false）
    返回值含义：
      {
        "code": 0, "message": "success",
        "data": {
          "count": 总用户数, "next": 下一页URL, "previous": 上一页URL,
          "results": [{"id": "uuid", "username": "admin", "name": "管理员", ...}]
        }
      }
    ID获取方式：data.results[].id → 用于delete_user/update_user
    """
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/users/users/"
    response = await send_api_request("GET", url, params=params.dict(exclude_none=True))
    return {"code": 0, "message": "success", "data": response}


@mcp.tool()
@validate_params(CreateUserParams)
async def create_user(params: CreateUserParams) -> dict:
    """
    功能说明：创建用户（文档2.2节“创建用户”）
    接口路径：POST /api/v1/users/users/
    参数说明：
      - username: 登录用户名（唯一）
      - name: 姓名
      - email: 邮箱
      - password: 密码（至少6位）
      - system_roles: 系统角色（[{\"pk\": "角色ID"}]，通过list_system_roles获取）
      - org_roles: 组织角色（[{\"pk\": "角色ID"}]，通过list_org_roles获取）
      - wechat/phone: 可选联系方式
      - groups: 关联用户组（[{\"pk\": "组ID"}]，通过list_user_groups获取）
    返回值含义：
      {
        "code": 0, "message": "用户xxx创建成功",
        "data": {"id": "uuid", "username": "xxx", "system_roles": [...], ...}
      }
    ID获取方式：data.id → 用于delete_user/update_user
    """
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/users/users/"
    response = await send_api_request("POST", url, json=params.dict(exclude_none=True))
    return {"code": 0, "message": f"用户{params.username}创建成功", "data": response}


@mcp.tool()
async def delete_user(user_id: str) -> dict:
    """
    功能说明：删除用户（文档2.3节“删除用户”）
    接口路径：DELETE /api/v1/users/users/{id}/
    参数说明：user_id: 用户ID（通过list_users获取）
    返回值含义：{"code": 0, "message": "用户uuid删除成功", "data": {"status": "ok"}}
    """
    try:
        validate_uuid(user_id)
    except ValueError as e:
        return {"code": -32602, "message": str(e), "data": {}}
    
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/users/users/{user_id}/"
    response = await send_api_request("DELETE", url)
    return {"code": 0, "message": f"用户{user_id}删除成功", "data": response}

# ====== 6. 章节3：用户组模块（文档第3章）======
class ListUserGroupsParams(BaseModel):
    limit: PositiveInt = Field(default=20, le=100)
    offset: int = Field(default=0, ge=0)
    name: Optional[str] = None


class CreateUserGroupParams(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    users: Optional[List[Dict[str, str]]] = None
    description: str = Field(default="")


@mcp.tool()
@validate_params(ListUserGroupsParams)
async def list_user_groups(params: ListUserGroupsParams) -> dict:
    """
    功能说明：查询用户组（文档3.1节“查询用户组”）
    接口路径：GET /api/v1/users/groups/
    参数说明：limit/offset（分页）、name（组名模糊匹配）
    返回值含义：
      {
        "code": 0, "message": "success",
        "data": {
          "count": 总组数, "results": [{"id": "uuid", "name": "开发组", ...}]
        }
      }
    ID获取方式：data.results[].id → 用于delete_user_group/create_asset_permission
    """
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/users/groups/"
    response = await send_api_request("GET", url, params=params.dict(exclude_none=True))
    return {"code": 0, "message": "success", "data": response}


@mcp.tool()
@validate_params(CreateUserGroupParams)
async def create_user_group(params: CreateUserGroupParams) -> dict:
    """
    功能说明：创建用户组（文档3.2节“创建用户组”）
    接口路径：POST /api/v1/users/groups/
    参数说明：
      - name: 组名（唯一）
      - users: 关联用户（[{\"pk\": "用户ID"}]，通过list_users获取）
      - description: 描述（可选）
    返回值含义：
      {
        "code": 0, "message": "用户组xxx创建成功",
        "data": {"id": "uuid", "name": "xxx", "users": [...], ...}
      }
    ID获取方式：data.id → 用于delete_user_group/create_asset_permission
    """
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/users/groups/"
    response = await send_api_request("POST", url, json=params.dict(exclude_none=True))
    return {"code": 0, "message": f"用户组{params.name}创建成功", "data": response}


@mcp.tool()
async def delete_user_group(group_id: str) -> dict:
    """
    功能说明：删除用户组（文档3.3节“删除用户组”）
    接口路径：DELETE /api/v1/users/groups/{id}/
    参数说明：group_id: 用户组ID（通过list_user_groups获取）
    返回值含义：{"code": 0, "message": "用户组uuid删除成功", "data": {"status": "ok"}}
    """
    try:
        validate_uuid(group_id)
    except ValueError as e:
        return {"code": -32602, "message": str(e), "data": {}}
    
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/users/groups/{group_id}/"
    response = await send_api_request("DELETE", url)
    return {"code": 0, "message": f"用户组{group_id}删除成功", "data": response}

# ====== 7. 章节7：资产节点模块（文档第7章）======
class ListNodesParams(BaseModel):
    limit: PositiveInt = Field(default=20, le=100)
    offset: int = Field(default=0, ge=0)
    search: Optional[str] = None
    full_value: Optional[str] = None
    value: Optional[str] = None


class CreateNodeParams(BaseModel):
    full_value: str = Field(...)
    value: Optional[str] = None


@mcp.tool()
@validate_params(ListNodesParams)
async def list_nodes(params: ListNodesParams) -> dict:
    """
    功能说明：查询资产节点（文档7.1节“查询节点”）
    接口路径：GET /api/v1/assets/nodes/
    参数说明：
      - limit/offset（分页）
      - search: 搜索节点名/路径
      - full_value: 完整路径（如 /Default/开发部门）
      - value: 节点名（如 开发部门）
    返回值含义：
      {
        "code": 0, "message": "success",
        "data": [{"id": "uuid", "full_value": "/Default/开发部门", ...}]
      }
    ID获取方式：data[].id → 用于delete_node/create_asset
    """
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/assets/nodes/"
    response = await send_api_request("GET", url, params=params.dict(exclude_none=True))
    return {"code": 0, "message": "success", "data": response}


@mcp.tool()
@validate_params(CreateNodeParams)
async def create_node(params: CreateNodeParams) -> dict:
    """
    功能说明：创建资产节点（文档7.2节“创建节点”）
    接口路径：POST /api/v1/assets/nodes/
    参数说明：
      - full_value: 完整路径（如 /Default/开发部门/北京机房，上级自动创建）
      - value: 节点名（可选，自动从full_value提取）
    返回值含义：
      {
        "code": 0, "message": "节点xxx创建成功",
        "data": {"id": "uuid", "full_value": "xxx", ...}
      }
    ID获取方式：data.id → 用于delete_node/create_asset
    """
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/assets/nodes/"
    response = await send_api_request("POST", url, json=params.dict(exclude_none=True))
    return {"code": 0, "message": f"节点{params.full_value}创建成功", "data": response}


@mcp.tool()
async def delete_node(node_id: str) -> dict:
    """
    功能说明：删除资产节点（文档7.4节“删除节点”）
    接口路径：DELETE /api/v1/assets/nodes/{id}/
    参数说明：node_id: 节点ID（通过list_nodes获取）
    返回值含义：{"code": 0, "message": "节点uuid删除成功", "data": {"status": "ok"}}
    """
    try:
        validate_uuid(node_id)
    except ValueError as e:
        return {"code": -32602, "message": str(e), "data": {}}
    
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/assets/nodes/{node_id}/"
    response = await send_api_request("DELETE", url)
    return {"code": 0, "message": f"节点{node_id}删除成功", "data": response}

# ====== 8. 章节8：标签模块（文档第8章）======
class ListLabelsParams(BaseModel):
    limit: PositiveInt = Field(default=20, le=100)
    offset: int = Field(default=0, ge=0)
    search: Optional[str] = None
    name: Optional[str] = None
    value: Optional[str] = None


class CreateLabelParams(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    value: str = Field(..., min_length=1, max_length=100)
    comment: str = Field(default="")


@mcp.tool()
@validate_params(ListLabelsParams)
async def list_labels(params: ListLabelsParams) -> dict:
    """
    功能说明：查询标签（文档8.1节“查询标签”）
    接口路径：GET /api/v1/assets/labels/
    参数说明：limit/offset（分页）、search/name/value（筛选）
    返回值含义：
      {
        "code": 0, "message": "success",
        "data": {
          "count": 总标签数, "results": [{"id": "uuid", "name": "环境", "value": "生产", ...}]
        }
      }
    ID获取方式：data.results[].id → 用于create_asset关联标签
    """
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/assets/labels/"
    response = await send_api_request("GET", url, params=params.dict(exclude_none=True))
    return {"code": 0, "message": "success", "data": response}


@mcp.tool()
@validate_params(CreateLabelParams)
async def create_label(params: CreateLabelParams) -> dict:
    """
    功能说明：创建标签（文档8.1节扩展，符合API规范）
    接口路径：POST /api/v1/assets/labels/
    参数说明：
      - name: 标签名（如“环境”）
      - value: 标签值（如“生产”）
      - comment: 描述（可选）
    返回值含义：
      {
        "code": 0, "message": "标签xxx:xxx创建成功",
        "data": {"id": "uuid", "name": "xxx", "value": "xxx", ...}
      }
    ID获取方式：data.id → 用于create_asset关联标签
    """
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/assets/labels/"
    response = await send_api_request("POST", url, json=params.dict(exclude_none=True))
    return {"code": 0, "message": f"标签{params.name}:{params.value}创建成功", "data": response}

# ====== 9. 章节10：资产模块（文档第10章）======
class ListAssetsParams(BaseModel):
    limit: PositiveInt = Field(default=20, le=100)
    offset: int = Field(default=0, ge=0)
    search: Optional[str] = None
    platform: Optional[str] = None
    name: Optional[str] = None
    address: Optional[Annotated[str, AfterValidator(validate_ipv4)]] = None
    node_id: Optional[Annotated[str, AfterValidator(validate_uuid)]] = None
    is_active: bool = Field(default=True)
    category: Optional[str] = None
    type: Optional[str] = None


class CreateHostAssetParams(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    address: Annotated[str, AfterValidator(validate_ipv4)] = Field(...)
    platform: Dict[str, str] = Field(...)
    nodes: List[Dict[str, str]] = Field(...)
    protocols: Optional[List[Dict[str, int]]] = Field(default=[{"name": "ssh", "port": 22}])
    labels: Optional[List[str]] = None
    is_active: bool = Field(default=True)
    comment: str = Field(default="")


@mcp.tool()
@validate_params(ListAssetsParams)
async def list_assets(params: ListAssetsParams) -> dict:
    """
    功能说明：查询资产（文档10.1节“查询资产”）
    接口路径：GET /api/v1/assets/assets/
    参数说明：
      - limit/offset（分页）
      - search/name/address（资产筛选）
      - node_id（节点筛选，通过list_nodes获取）
      - platform（平台筛选，通过list_platforms获取）
      - is_active/category/type（状态/类别/类型筛选）
    返回值含义：
      {
        "code": 0, "message": "success",
        "data": {
          "count": 总资产数, "results": [{"id": "uuid", "name": "服务器1", "address": "192.168.1.1", ...}]
        }
      }
    ID获取方式：data.results[].id → 用于delete_asset/create_asset_permission
    """
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/assets/assets/"
    response = await send_api_request("GET", url, params=params.dict(exclude_none=True))
    return {"code": 0, "message": "success", "data": response}


@mcp.tool()
@validate_params(CreateHostAssetParams)
async def create_host_asset(params: CreateHostAssetParams) -> dict:
    """
    功能说明：创建主机资产（文档10.3.2节“创建主机资产”）
    接口路径：POST /api/v1/assets/hosts/
    参数说明：
      - name: 资产名（唯一）
      - address: IPv4地址
      - platform: 平台（{\"pk\": "ID"}，1=Linux/5=Windows，通过list_platforms获取）
      - nodes: 关联节点（[{\"pk\": "ID"}]，通过list_nodes获取）
      - protocols: 协议/端口（默认ssh:22）
      - labels: 关联标签ID（通过list_labels获取）
    返回值含义：
      {
        "code": 0, "message": "主机xxx创建成功",
        "data": {"id": "uuid", "name": "xxx", "address": "xxx", ...}
      }
    ID获取方式：data.id → 用于delete_asset/create_asset_permission
    """
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/assets/hosts/"
    platform_pk = params.platform.get("pk")
    if not platform_pk:
        return {"code": -32602, "message": "platform需包含pk字段", "data": {}}
    
    response = await send_api_request(
        "POST", url, params={"platform": platform_pk}, json=params.dict(exclude_none=True)
    )
    return {"code": 0, "message": f"主机{params.name}创建成功", "data": response}


@mcp.tool()
async def delete_asset(asset_id: str) -> dict:
    """
    功能说明：删除资产（文档10.3.4节“删除主机资产”）
    接口路径：DELETE /api/v1/assets/assets/{id}/
    参数说明：asset_id: 资产ID（通过list_assets获取）
    返回值含义：{"code": 0, "message": "资产uuid删除成功", "data": {"status": "ok"}}
    """
    try:
        validate_uuid(asset_id)
    except ValueError as e:
        return {"code": -32602, "message": str(e), "data": {}}
    
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/assets/assets/{asset_id}/"
    response = await send_api_request("DELETE", url)
    return {"code": 0, "message": f"资产{asset_id}删除成功", "data": response}

# ====== 10. 章节10：资产授权模块（文档第10章，补全截断）======
class ListAssetPermissionsParams(BaseModel):
    limit: PositiveInt = Field(default=20, le=100)
    offset: int = Field(default=0, ge=0)
    search: Optional[str] = None
    name: Optional[str] = None
    node_id: Optional[Annotated[str, AfterValidator(validate_uuid)]] = None
    asset_id: Optional[Annotated[str, AfterValidator(validate_uuid)]] = None
    asset_name: Optional[str] = None
    user_id: Optional[Annotated[str, AfterValidator(validate_uuid)]] = None
    username: Optional[str] = None
    user_group: Optional[Annotated[str, AfterValidator(validate_uuid)]] = None
    address: Optional[Annotated[str, AfterValidator(validate_ipv4)]] = None
    accounts: Optional[str] = None
    is_valid: Optional[int] = None
    is_effective: int = Field(default=1)
    from_ticket: Optional[int] = None


class CreateAssetPermissionParams(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    users: List[Dict[str, str]] = Field(default=[])
    user_groups: List[Dict[str, str]] = Field(default=[])
    assets: List[Annotated[str, AfterValidator(validate_uuid)]] = Field(default=[])
    nodes: List[Annotated[str, AfterValidator(validate_uuid)]] = Field(default=[])
    accounts: List[str] = Field(default=["@ALL"])
    actions: List[str] = Field(...)
    protocols: List[str] = Field(default=["all"])
    is_active: bool = Field(default=True)
    date_start: Optional[str] = None
    date_expired: Optional[str] = None
    comment: str = Field(default="")

    @field_validator("users", "user_groups")
    def check_principal(cls, v, values):
        data = values.data  # 获取所有字段的值（dict）
        #if len(data.get("users", [])) == 0 and len(data.get("user_groups", [])) == 0:
        #    raise ValueError("users/user_groups至少填一个")
        return v

    @field_validator("assets", "nodes")
    def check_resource(cls, v, values):
        data = values.data  # 获取所有字段的值（dict）
        #if len(data.get("assets", [])) == 0 and len(data.get("nodes", [])) == 0:
        #    raise ValueError("assets/nodes至少填一个")
        return v


class ListPermAccountsParams(BaseModel):
    """查询资产授权账号参数（文档10.5节Query Parameters）"""
    limit: PositiveInt = Field(default=20, le=100)
    offset: int = Field(default=0, ge=0)
    search: Optional[str] = None
    name: Optional[str] = None
    username: Optional[str] = None
    version: Optional[str] = None
    privileged: Optional[bool] = None


@mcp.tool()
@validate_params(ListAssetPermissionsParams)
async def list_asset_permissions(params: ListAssetPermissionsParams) -> dict:
    """
    功能说明：查询资产授权（文档10.1节“查询资产授权”）
    接口路径：GET /api/v1/perms/asset-permissions/
    参数说明：
      - limit/offset（分页）
      - name/node_id/asset_id（授权筛选）
      - user_id/user_group（用户/组筛选）
      - is_effective（是否生效，默认1=生效）
    返回值含义：
      {
        "code": 0, "message": "success",
        "data": {
          "count": 总授权数, "results": [{"id": "uuid", "name": "授权1", "users": [...], ...}]
        }
      }
    ID获取方式：data.results[].id → 用于delete_asset_permission/update_asset_permission
    """
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/perms/asset-permissions/"
    response = await send_api_request("GET", url, params=params.dict(exclude_none=True))
    return {"code": 0, "message": "success", "data": response}


@mcp.tool()
@validate_params(CreateAssetPermissionParams)
async def create_asset_permission(params: CreateAssetPermissionParams) -> dict:
    """
    功能说明：创建资产授权（文档10.2节“创建资产授权”）
    接口路径：POST /api/v1/perms/asset-permissions/
    参数说明：
      - name: 授权名（唯一）
      - users/user_groups: 关联用户/组（ID通过list_users/list_user_groups获取）
      - assets/nodes: 关联资产/节点（["ID1","ID2","ID3"], ID通过list_assets/list_nodes获取）
      - accounts: 授权账号（@ALL/@USER/@SPEC/@INPUT，默认@ALL）
      - actions: 操作权限（connect/upload/download等，必选）
      - protocols: 协议（ssh/rdp/all等，默认all）
      - date_start/date_expired: 生效/过期时间（ISO格式）
    返回值含义：
      {
        "code": 0, "message": "授权xxx创建成功",
        "data": {"id": "uuid", "name": "xxx", "users": [...], ...}
      }
    ID获取方式：data.id → 用于delete_asset_permission/update_asset_permission
    """
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/perms/asset-permissions/"
    response = await send_api_request("POST", url, json=params.dict(exclude_none=True))
    return {"code": 0, "message": f"资产授权{params.name}创建成功", "data": response}


@mcp.tool()
async def delete_asset_permission(perm_id: str) -> dict:
    """
    功能说明：删除资产授权（文档10.3节“删除资产授权”）
    接口路径：DELETE /api/v1/perms/asset-permissions/{id}/
    参数说明：perm_id: 授权ID（通过list_asset_permissions获取）
    返回值含义：{"code": 0, "message": "授权uuid删除成功", "data": {"status": "ok"}}
    """
    try:
        validate_uuid(perm_id)
    except ValueError as e:
        return {"code": -32602, "message": str(e), "data": {}}
    
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/perms/asset-permissions/{perm_id}/"
    response = await send_api_request("DELETE", url)
    return {"code": 0, "message": f"资产授权{perm_id}删除成功", "data": response}


@mcp.tool()
async def update_asset_permission(perm_id: str, params: dict) -> dict:
    """
    功能说明：更新资产授权（文档10.4节“更新资产授权”）
    接口路径：PUT /api/v1/perms/asset-permissions/{id}/
    参数说明：
      - perm_id: 授权ID（通过list_asset_permissions获取）
      - params: 同CreateAssetPermissionParams（全量更新）
    返回值含义：
      {
        "code": 0, "message": "授权uuid更新成功",
        "data": {"id": "uuid", "name": "更新后授权", ...}
      }
    """
    try:
        validate_uuid(perm_id)
        validated_params = CreateAssetPermissionParams(** params)
    except (ValueError, ValidationError) as e:
        return {"code": -32602, "message": str(e), "data": {}}
    
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/perms/asset-permissions/{perm_id}/"
    response = await send_api_request("PUT", url, json=validated_params.dict(exclude_none=True))
    return {"code": 0, "message": f"资产授权{perm_id}更新成功", "data": response}


@mcp.tool()
@validate_params(ListPermAccountsParams)
async def get_asset_permission_accounts(perm_id: str, params: ListPermAccountsParams) -> dict:
    """
    功能说明：查询资产授权关联账号（文档10.5节“查询资产授权账号”，补全截断）
    接口路径：GET /api/v1/perms/asset-permissions/{id}/accounts/
    参数说明：
      - perm_id: 授权ID（必选，通过list_asset_permissions获取）
      - limit/offset: 分页参数（必选）
      - search/name/username: 账号筛选（可选）
      - privileged: 是否特权账号（可选，true/false）
    参数要求：
      - perm_id需为32位UUID格式
      - limit最大100，offset不能为负数
    返回值含义：
      {
        "code": 0,
        "message": "success",
        "data": {
          "count": 5（关联账号总数）,
          "next": null（下一页URL）,
          "previous": null（上一页URL）,
          "results": [
            {
              "id": "uuid"（账号ID）,
              "name": "root账号"（账号名称）,
              "username": "root"（账号用户名）,
              "asset": {
                "id": "uuid"（关联资产ID）,
                "name": "生产服务器-192.168.1.101"（资产名）,
                "address": "192.168.1.101"（资产IP）
              },
              "privileged": true（是否特权账号）,
              "is_active": true（是否激活）,
              "date_created": "2024/10/01 10:00:00 +0800"（创建时间）
            }
          ]
        }
      }
    ID获取方式：
      - perm_id通过list_asset_permissions接口的data.results[].id获取
      - 返回的data.results[].id为账号ID，可用于get_account_secret/delete_account接口
    """
    # 校验授权ID格式
    try:
        validate_uuid(perm_id)
    except ValueError as e:
        return {"code": -32602, "message": str(e), "data": {}}
    
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/perms/asset-permissions/{perm_id}/accounts/"
    response = await send_api_request(
        method="GET",
        url=url,
        params=params.dict(exclude_none=True)
    )
    return {"code": 0, "message": "success", "data": response}

# ====== 11. 章节14：工单模块（文档第14章，完整补充）======
class CreateTicketParams(BaseModel):
    """创建工单参数（文档14.1节Request Body）"""
    title: str = Field(..., min_length=1, max_length=200)
    org_id: Annotated[str, AfterValidator(validate_uuid)] = Field(...)
    apply_assets: Optional[List[Annotated[str, AfterValidator(validate_uuid)]]] = None
    apply_node: Optional[Annotated[str, AfterValidator(validate_uuid)]] = None
    apply_accounts: List[str] = Field(default=["@ALL"])
    apply_actions: List[str] = Field(default=["all"])
    apply_date_start: str = Field(...)
    apply_date_expired: str = Field(...)
    comment: str = Field(default="")

    @field_validator("apply_assets", "apply_node")
    def check_resource(cls, v, values):
        if len(values.get("apply_assets", [])) == 0 and not values.get("apply_node"):
            raise ValueError("apply_assets/apply_node至少填一个")
        return v


class ListTicketsParams(BaseModel):
    """查询工单参数（文档14.2节Query Parameters）"""
    limit: PositiveInt = Field(default=20, le=100)
    offset: int = Field(default=0, ge=0)
    state: Optional[str] = Field(None, description="pending/approved/rejected")
    status: Optional[str] = Field(None, description="open/closed")
    type: Optional[str] = Field(None, description="apply_asset/login_confirm等")


class ApproveTicketParams(BaseModel):
    """审批工单参数（文档14.3节Request Body）"""
    comment: str = Field(default="", description="审批备注")


@mcp.tool()
@validate_params(CreateTicketParams)
async def create_ticket(params: CreateTicketParams) -> dict:
    """
    功能说明：创建资产访问工单（文档14.1节“创建工单”）
    接口路径：POST /api/v1/tickets/apply-asset-tickets/open/
    参数说明：
      - title: 工单标题（如“申请访问生产服务器”）
      - org_id: 组织ID（默认00000000-0000-0000-0000-000000000002）
      - apply_assets: 申请资产ID（通过list_assets获取）
      - apply_node: 申请节点ID（通过list_nodes获取）
      - apply_accounts: 申请账号（@ALL/@USER等，默认@ALL）
      - apply_actions: 申请权限（connect/all等，默认all）
      - apply_date_start/apply_date_expired: 生效/过期时间（ISO格式，必选）
    返回值含义：
      {
        "code": 0, "message": "工单xxx创建成功",
        "data": {
          "id": "uuid"（工单ID）,
          "title": "xxx"（工单标题）,
          "serial_num": "202410010001"（工单编号）,
          "state": {"value": "pending", "label": "待处理"},
          "apply_assets": [{"id": "uuid", "name": "服务器1"}],
          ...
        }
      }
    ID获取方式：data.id → 用于approve_ticket/list_tickets
    """
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/tickets/apply-asset-tickets/open/"
    response = await send_api_request("POST", url, json=params.dict(exclude_none=True))
    return {"code": 0, "message": f"工单{params.title}创建成功", "data": response}


@mcp.tool()
@validate_params(ListTicketsParams)
async def list_tickets(params: ListTicketsParams) -> dict:
    """
    功能说明：查询工单列表（文档14.2节“获取工单”）
    接口路径：GET /api/v1/tickets/tickets/
    参数说明：
      - limit/offset（分页）
      - state: 工单状态（pending/approved/rejected）
      - status: 工单状态（open/closed）
      - type: 工单类型（apply_asset/login_confirm等）
    返回值含义：
      {
        "code": 0, "message": "success",
        "data": [
          {
            "id": "uuid"（工单ID）,
            "title": "申请访问服务器",
            "serial_num": "202410010001",
            "state": {"value": "pending", "label": "待处理"},
            ...
          }
        ]
      }
    ID获取方式：data[].id → 用于approve_ticket
    """
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/tickets/tickets/"
    response = await send_api_request("GET", url, params=params.dict(exclude_none=True))
    return {"code": 0, "message": "success", "data": response}


@mcp.tool()
@validate_params(ApproveTicketParams)
async def approve_ticket(ticket_id: str, params: ApproveTicketParams, approve: bool = True) -> dict:
    """
    功能说明：审批工单（文档14.3节“审批工单”）
    接口路径：PATCH /api/v1/tickets/apply-asset-tickets/{id}/approve/（同意）
              PATCH /api/v1/tickets/apply-asset-tickets/{id}/reject/（拒绝）
    参数说明：
      - ticket_id: 工单ID（通过list_tickets获取）
      - params.comment: 审批备注（可选）
      - approve: 是否同意（true=同意，false=拒绝）
    返回值含义：
      {
        "code": 0, 
        "message": "工单uuid已同意"（或“已拒绝”）,
        "data": "ok"（文档14.3节返回示例）
      }
    """
    try:
        validate_uuid(ticket_id)
    except ValueError as e:
        return {"code": -32602, "message": str(e), "data": {}}
    
    # 选择审批接口（同意/拒绝）
    action = "approve" if approve else "reject"
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/tickets/apply-asset-tickets/{ticket_id}/{action}/"
    response = await send_api_request("PATCH", url, json=params.dict(exclude_none=True))
    
    return {
        "code": 0, 
        "message": f"工单{ticket_id}已{'同意' if approve else '拒绝'}", 
        "data": response
    }


@mcp.tool()
async def get_ticket_flow(ticket_id: str) -> dict:
    """
    功能说明：查询工单审批流程（文档14.4节“查询流程”扩展）
    接口路径：GET /api/v1/tickets/apply-asset-tickets/{id}/flow/
    参数说明：ticket_id: 工单ID（通过list_tickets获取）
    返回值含义：
      {
        "code": 0, "message": "success",
        "data": {
          "process_map": [
            {
              "state": "pending",
              "assignees": ["uuid"],
              "processor": "uuid",
              "approval_date": "2024/10/01 10:00:00 +0800"
            }
          ]
        }
      }
    """
    try:
        validate_uuid(ticket_id)
    except ValueError as e:
        return {"code": -32602, "message": str(e), "data": {}}
    
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/tickets/apply-asset-tickets/{ticket_id}/flow/"
    response = await send_api_request("GET", url)
    return {"code": 0, "message": "success", "data": response}



# ====== 5. 第9章：资产账号管理（文档第9章，全量新增）======
# 9.1 公共模型：账号基础字段（文档9.2/9.3/9.5节通用）
class AccountBaseParams(BaseModel):
    """资产账号基础参数（文档9.2节Request Body公共字段）"""
    name: str = Field(..., min_length=1, max_length=100, description="账号名称（如'root-生产服务器'，唯一标识）")
    username: str = Field(..., min_length=1, max_length=100, description="登录用户名（资产端实际用户名，如'root'）")
    secret_type: str = Field(
        default="password", 
        description="密文类型（文档9.2节可选值：password=密码，ssh_key=SSH密钥）"
    )
    secret: Optional[str] = Field(None, description="密码/密钥内容（secret_type=password时必填，至少6位）")
    passphrase: Optional[str] = Field(None, description="密钥密码（secret_type=ssh_key时可选，用于解密密钥）")
    privileged: bool = Field(default=False, description="是否特权账号（文档9.2节：可执行sudo等高级操作）")
    is_active: bool = Field(default=True, description="是否激活（未激活账号无法用于登录）")
    comment: str = Field(default="", description="账号备注（如'生产环境管理员账号'）")

    # 自定义校验：secret_type=password时必须传secret（文档9.2节约束）
    @field_validator("secret")
    def secret_required_for_password(cls, v, values):
        if values.get("secret_type") == "password" and not v:
            raise ValueError("secret_type=password时，必须填写secret（密码）")
        return v


# 9.2 接口1：查询账号列表（文档9.1节）
class ListAccountsParams(BaseModel):
    """查询账号列表参数（文档9.1节Query Parameters）"""
    limit: PositiveInt = Field(default=20, le=100, description="每页条数（最大100）")
    offset: int = Field(default=0, ge=0, description="分页偏移量（从0开始）")
    node_id: Optional[Annotated[str, AfterValidator(validate_uuid)]] = Field(
        None, 
        description="节点ID（筛选该节点下资产的账号，通过list_nodes获取）"
    )
    asset_id: Optional[Annotated[str, AfterValidator(validate_uuid)]] = Field(
        None, 
        description="资产ID（筛选指定资产的账号，通过list_assets获取）"
    )
    id: Optional[Annotated[str, AfterValidator(validate_uuid)]] = Field(
        None, 
        description="账号ID（精确匹配，通过本接口返回值获取）"
    )
    username: Optional[str] = Field(None, description="用户名（模糊匹配，如'root'）")
    has_secret: Optional[bool] = Field(None, description="是否托管密码（true=已托管，false=未托管）")


@mcp.tool()
@validate_params(ListAccountsParams)
async def list_accounts(params: ListAccountsParams) -> dict:
    """
    功能说明：分页查询资产账号列表，支持节点、资产、用户名多条件过滤（文档9.1节“查询账号”）
    接口路径：GET /api/v1/accounts/accounts/（文档9.1节API地址）
    参数说明：
      - limit: 每页条数，默认20，最大100（必选）
      - offset: 偏移量，默认0（必选）
      - node_id: 节点ID（可选，需通过list_nodes接口获取）
      - asset_id: 资产ID（可选，需通过list_assets接口获取）
      - id: 账号ID（可选，精确匹配，需通过本接口返回的data.results[].id获取）
      - username: 用户名（可选，模糊匹配）
      - has_secret: 是否托管密码（可选，true/false）
    参数要求：
      - node_id/asset_id/id需为32位UUID格式
      - limit不能超过100，offset不能为负数
    返回值含义：
      {
        "code": 0（成功）/-32602（参数错误）,
        "message": "success",
        "data": {
          "count": 50（总账号数）,
          "next": "http://...?limit=20&offset=20"（下一页URL，null表示无）,
          "previous": null（上一页URL，null表示无）,
          "results": [
            {
              "id": "uuid"（账号ID，用于delete_account/get_account_secret）,
              "name": "root-生产服务器",
              "username": "root",
              "secret_type": {"value": "password", "label": "密码"},
              "asset": {
                "id": "uuid"（关联资产ID）,
                "name": "生产服务器-192.168.1.101",
                "address": "192.168.1.101"
              },
              "privileged": true（是否特权账号）,
              "is_active": true（是否激活）,
              "has_secret": true（是否托管密码）
            }
          ]
        }
      }
    ID获取方式：
      - 账号ID：data.results[].id → 用于delete_account/update_account/get_account_secret
      - 资产ID：通过list_assets获取 → 用于create_account的asset参数
      - 节点ID：通过list_nodes获取 → 用于筛选节点下的账号
    """
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/accounts/accounts/"
    response = await send_api_request(
        method="GET",
        url=url,
        params=params.dict(exclude_none=True)
    )
    return {"code": 0, "message": "success", "data": response}


# 9.3 接口2：创建资产账号（文档9.2节）
class CreateAccountParams(AccountBaseParams):
    """创建账号参数（文档9.2节Request Body）"""
    asset: Annotated[str, AfterValidator(validate_uuid)] = Field(
        ..., 
        description="资产ID（必填，账号所属资产，通过list_assets获取）"
    )
    push_now: bool = Field(
        default=False, 
        description="是否立即推送账号到资产（true=创建后同步到资产系统，文档9.2节）"
    )


@mcp.tool()
@validate_params(CreateAccountParams)
async def create_account(params: CreateAccountParams) -> dict:
    """
    功能说明：为指定资产创建单个账号，支持密码/SSH密钥托管（文档9.2节“创建资产账号”）
    接口路径：POST /api/v1/accounts/accounts/（文档9.2节API地址）
    参数说明：
      - 继承AccountBaseParams的所有字段（name/username/secret_type等）
      - asset: 资产ID（必选，通过list_assets获取）
      - push_now: 是否立即推送（可选，默认false）
    参数要求：
      - asset需为32位UUID格式
      - secret_type=password时，secret至少6位（建议包含大小写字母、数字）
      - name在同一资产下需唯一
    返回值含义：
      {
        "code": 0（成功）/-32602（参数错误）,
        "message": "账号root创建成功（资产ID：uuid）",
        "data": {
          "id": "uuid"（新创建账号的ID）,
          "name": "root-生产服务器",
          "username": "root",
          "asset": {
            "id": "uuid",
            "name": "生产服务器-192.168.1.101"
          },
          "secret_type": {"value": "password", "label": "密码"},
          "privileged": true,
          "is_active": true,
          "date_created": "2024/10/01 10:00:00 +0800"
        }
      }
    ID获取方式：
      - 资产ID：通过list_assets接口的data.results[].id获取
      - 账号ID：返回的data.id → 用于delete_account/update_account
    """
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/accounts/accounts/"
    response = await send_api_request(
        method="POST",
        url=url,
        json=params.dict(exclude_none=True)
    )
    return {
        "code": 0,
        "message": f"账号{params.username}创建成功（资产ID：{params.asset}）",
        "data": response
    }


# 9.4 接口3：批量创建资产账号（文档9.3节）
class BatchCreateAccountsParams(AccountBaseParams):
    """批量创建账号参数（文档9.3节Request Body）"""
    assets: List[Annotated[str, AfterValidator(validate_uuid)]] = Field(
        ..., 
        description="资产ID列表（必填，一次性为多个资产创建相同账号，通过list_assets获取）"
    )
    on_invalid: str = Field(
        default="error", 
        description="账号冲突策略（文档9.3节可选值：error=冲突报错，update=覆盖更新，skip=跳过冲突）"
    )
    push_now: bool = Field(default=False, description="是否立即推送账号到所有资产")

    # 自定义校验：on_invalid必须为合法值
    @field_validator("on_invalid")
    def on_invalid_must_be_valid(cls, v):
        valid_values = ["error", "update", "skip"]
        if v not in valid_values:
            raise ValueError(f"on_invalid必须为{valid_values}中的一个，当前输入：{v}")
        return v

    # 自定义校验：assets列表不能为空
    @field_validator("assets")
    def assets_cannot_be_empty(cls, v):
        if len(v) == 0:
            raise ValueError("assets列表不能为空，至少需指定一个资产ID")
        return v


@mcp.tool()
@validate_params(BatchCreateAccountsParams)
async def batch_create_accounts(params: BatchCreateAccountsParams) -> dict:
    """
    功能说明：一次性为多个资产创建相同账号（如为10台Linux服务器创建root账号，文档9.3节“批量创建资产账号”）
    接口路径：POST /api/v1/accounts/accounts/bulk/（文档9.3节API地址）
    参数说明：
      - 继承AccountBaseParams的所有字段（name/username/secret_type等）
      - assets: 资产ID列表（必选，通过list_assets获取，至少1个）
      - on_invalid: 冲突策略（可选，默认error）
      - push_now: 是否立即推送（可选，默认false）
    参数要求：
      - assets中每个ID需为32位UUID格式
      - secret_type=password时，secret至少6位
      - 同一资产下账号名（name）需唯一
    返回值含义：
      {
        "code": 0（成功）/-32602（参数错误）,
        "message": "已为5个资产批量创建账号root",
        "data": [
          {
            "asset": "生产服务器-192.168.1.101(192.168.1.101)",
            "state": "created"（状态：created=创建成功，updated=已更新，skipped=已跳过）,
            "changed": true（是否变更）
          }
        ]
      }
    ID获取方式：
      - 资产ID：通过list_assets接口的data.results[].id获取，批量传入assets列表
    """
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/accounts/accounts/bulk/"
    response = await send_api_request(
        method="POST",
        url=url,
        json=params.dict(exclude_none=True)
    )
    return {
        "code": 0,
        "message": f"已为{len(params.assets)}个资产批量创建账号{params.username}",
        "data": response
    }


# 9.5 接口4：删除资产账号（文档9.4节）
@mcp.tool()
async def delete_account(account_id: str) -> dict:
    """
    功能说明：根据账号ID删除指定资产账号（文档9.4节“删除资产账号”）
    接口路径：DELETE /api/v1/accounts/accounts/{id}/（文档9.4节API地址）
    参数说明：
      - account_id: 账号ID（必选，通过list_accounts接口获取）
    参数要求：
      - account_id需为32位UUID格式（如c8782db3-5f3d-4b70-80b5-6f23962fc16b）
      - 不能删除已关联改密计划的账号（需先删除改密计划）
    返回值含义：
      {
        "code": 0（成功）/-32602（参数错误）,
        "message": "账号uuid删除成功",
        "data": {"status": "ok"}
      }
    ID获取方式：
      - 账号ID：通过list_accounts接口的data.results[].id获取
    """
    # 校验账号ID格式
    try:
        validate_uuid(account_id)
    except ValueError as e:
        return {"code": -32602, "message": str(e), "data": {}}
    
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/accounts/accounts/{account_id}/"
    response = await send_api_request(method="DELETE", url=url)
    return {"code": 0, "message": f"账号{account_id}删除成功", "data": response}


# 9.6 接口5：更新资产账号（文档9.5节）
class UpdateAccountParams(AccountBaseParams):
    """更新账号参数（文档9.5节Request Body）"""
    su_from: Optional[Annotated[str, AfterValidator(validate_uuid)]] = Field(
        None, 
        description="切换自账号ID（文档9.5节：如从普通账号切换到root，需指定普通账号ID，通过list_accounts获取）"
    )


@mcp.tool()
async def update_account(account_id: str, params: dict) -> dict:
    """
    功能说明：根据账号ID全量更新账号信息（如修改密码、特权状态，文档9.5节“更新资产账号”）
    接口路径：PUT /api/v1/accounts/accounts/{id}/（文档9.5节API地址）
    参数说明：
      - account_id: 账号ID（必选，通过list_accounts获取）
      - params: 更新参数（同UpdateAccountParams模型，含name/username/secret等）
    参数要求：
      - account_id需为32位UUID格式
      - params需包含所有必选字段（全量更新，如name/username/secret_type）
      - secret_type=password时，secret至少6位
    返回值含义：
      {
        "code": 0（成功）/-32602（参数错误）,
        "message": "账号uuid更新成功",
        "data": {
          "id": "uuid",
          "name": "root-生产服务器（更新后）",
          "username": "root",
          "secret_type": {"value": "password", "label": "密码"},
          "privileged": false（更新后的特权状态）,
          "date_updated": "2024/10/01 11:00:00 +0800"
        }
      }
    ID获取方式：
      - 账号ID：通过list_accounts接口的data.results[].id获取
      - su_from账号ID：通过list_accounts接口获取（如需设置切换自账号）
    """
    # 1. 校验账号ID格式
    try:
        validate_uuid(account_id)
    except ValueError as e:
        return {"code": -32602, "message": str(e), "data": {}}
    
    # 2. 校验更新参数
    try:
        validated_params = UpdateAccountParams(** params)
    except ValidationError as e:
        errors = []
        for err in e.errors():
            errors.append({
                "field": ".".join(str(loc) for loc in err["loc"]),
                "message": err["msg"],
                "input": err.get("input")
            })
        return {"code": -32602, "message": "参数错误", "data": {"details": errors}}
    
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/accounts/accounts/{account_id}/"
    response = await send_api_request(
        method="PUT",
        url=url,
        json=validated_params.dict(exclude_none=True)
    )
    return {"code": 0, "message": f"账号{account_id}更新成功", "data": response}


# 9.7 接口6：查询账号密码（文档9.6节）
@mcp.tool()
async def get_account_secret(account_id: str) -> dict:
    """
    功能说明：查询账号托管的密码/密钥（文档9.6节“查询密码”）
    接口路径：GET /api/v1/accounts/account-secrets/{id}/（文档9.6节API地址）
    前提条件：需在JumpServer配置文件中设置 SECURITY_VIEW_AUTH_NEED_MFA=False，重启服务生效（文档9.6节前言）
    参数说明：
      - account_id: 账号ID（必选，通过list_accounts获取）
    参数要求：
      - account_id需为32位UUID格式
      - 账号必须已托管密码（has_secret=true，通过list_accounts判断）
    返回值含义：
      {
        "code": 0（成功）/-32602（参数错误）,
        "message": "已获取账号uuid的密码",
        "data": {
          "id": "uuid",
          "username": "root",
          "secret_type": {"value": "password", "label": "密码"},
          "secret": "Password@123"（明文密码/密钥）,
          "asset": {
            "id": "uuid",
            "name": "生产服务器-192.168.1.101"
          },
          "privileged": true
        }
      }
    ID获取方式：
      - 账号ID：通过list_accounts接口的data.results[].id获取（需确保has_secret=true）
    """
    # 校验账号ID格式
    try:
        validate_uuid(account_id)
    except ValueError as e:
        return {"code": -32602, "message": str(e), "data": {}}
    
    # 提示前提条件
    logger.warning(
        f"调用get_account_secret接口，需确保JumpServer已配置 SECURITY_VIEW_AUTH_NEED_MFA=False 并重启"
    )
    
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/accounts/account-secrets/{account_id}/"
    response = await send_api_request(method="GET", url=url)
    return {"code": 0, "message": f"已获取账号{account_id}的密码", "data": response}

# ====== 6. 第14章：审计日志（文档第14章，全量新增）======
# 14.1 接口1：获取会话记录（文档14.1节）
class ListSessionsParams(BaseModel):
    """查询会话记录参数（文档14.1节Query Parameters）"""
    limit: PositiveInt = Field(default=20, le=100, description="每页条数（最大100）")
    offset: int = Field(default=0, ge=0, description="分页偏移量（从0开始）")
    user_id: Optional[Annotated[str, AfterValidator(validate_uuid)]] = Field(
        None, 
        description="用户ID（筛选指定用户的会话，通过list_users获取）"
    )
    asset_id: Optional[Annotated[str, AfterValidator(validate_uuid)]] = Field(
        None, 
        description="资产ID（筛选指定资产的会话，通过list_assets获取）"
    )
    order: Optional[str] = Field(default="-date_start", description="排序字段（如date_start/-date_start，默认倒序）")
    date_from: str = Field(..., description="开始时间（必选，格式：2024-10-01T00:00:00Z）")
    date_to: str = Field(..., description="结束时间（必选，格式：2024-10-01T23:59:59Z）")
    is_finished: int = Field(default=1, description="是否结束（1=已结束，0=未结束，默认1）")

    # 自定义校验：时间格式（简化ISO格式校验）
    @field_validator("date_from", "date_to")
    def date_format_check(cls, v):
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"时间格式错误：{v}，需符合ISO格式（如2024-10-01T00:00:00Z）")
        return v


@mcp.tool()
@validate_params(ListSessionsParams)
async def list_sessions(params: ListSessionsParams) -> dict:
    """
    功能说明：分页查询资产访问会话记录（如SSH/RDP连接记录，文档14.1节“获取会话记录”）
    接口路径：GET /api/v1/terminal/sessions/（文档14.1节API地址）
    参数说明：
      - limit/offset: 分页参数（必选）
      - user_id: 用户ID（可选，通过list_users获取）
      - asset_id: 资产ID（可选，通过list_assets获取）
      - order: 排序（可选，默认按开始时间倒序）
      - date_from/date_to: 时间范围（必选，ISO格式）
      - is_finished: 是否结束（可选，默认1=已结束）
    参数要求：
      - user_id/asset_id需为32位UUID格式
      - date_from不能晚于date_to
      - limit不能超过100
    返回值含义：
      {
        "code": 0（成功）/-32602（参数错误）,
        "message": "success",
        "data": {
          "count": 100（总会话数）,
          "next": null,
          "previous": null,
          "results": [
            {
              "id": "uuid"（会话ID，用于list_commands获取命令记录）,
              "user": "admin(admin)",
              "asset": "生产服务器-192.168.1.101(192.168.1.101)",
              "account": "root(root)",
              "protocol": "ssh",
              "type": {"value": "ssh", "label": "SSH"},
              "login_from": {"value": "WT", "label": "Web Terminal"},
              "remote_addr": "10.1.240.254",
              "is_finished": true,
              "has_replay": true（是否有录像）,
              "date_start": "2024/10/01 10:00:00 +0800",
              "date_end": "2024/10/01 10:30:00 +0800"
            }
          ]
        }
      }
    ID获取方式：
      - 会话ID：data.results[].id → 用于list_commands接口
      - 用户ID：通过list_users获取 → 筛选用户会话
      - 资产ID：通过list_assets获取 → 筛选资产会话
    """
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/terminal/sessions/"
    response = await send_api_request(
        method="GET",
        url=url,
        params=params.dict(exclude_none=True)
    )
    return {"code": 0, "message": "success", "data": response}


# 14.2 接口2：获取命令记录（文档14.2节）
class ListCommandsParams(BaseModel):
    """查询命令记录参数（文档14.2节Query Parameters）"""
    session_id: Annotated[str, AfterValidator(validate_uuid)] = Field(
        ..., 
        description="会话ID（必选，通过list_sessions获取）"
    )
    limit: PositiveInt = Field(default=20, le=100, description="每页条数（最大100）")
    offset: int = Field(default=0, ge=0, description="分页偏移量（从0开始）")


@mcp.tool()
@validate_params(ListCommandsParams)
async def list_commands(params: ListCommandsParams) -> dict:
    """
    功能说明：查询指定会话的命令执行记录（如SSH命令输入/输出，文档14.2节“获取命令记录”）
    接口路径：GET /api/v1/terminal/commands/（文档14.2节API地址）
    参数说明：
      - session_id: 会话ID（必选，通过list_sessions获取）
      - limit/offset: 分页参数（必选）
    参数要求：
      - session_id需为32位UUID格式
      - limit不能超过100，offset不能为负数
    返回值含义：
      {
        "code": 0（成功）/-32602（参数错误）,
        "message": "success",
        "data": {
          "count": 50（总命令数）,
          "next": null,
          "previous": null,
          "results": [
            {
              "id": "uuid"（命令ID）,
              "user": "admin",
              "asset": "生产服务器-192.168.1.101",
              "account": "root(root)",
              "input": "docker ps -a",  # 命令输入
              "output": "CONTAINER ID   IMAGE   ...",  # 命令输出
              "risk_level": {"value": 0, "label": "接受"},  # 风险等级
              "timestamp_display": "2024/10/01 10:05:00 +0800",  # 执行时间
              "remote_addr": "10.1.240.254"
            }
          ]
        }
      }
    ID获取方式：
      - 会话ID：通过list_sessions接口的data.results[].id获取（必选）
    """
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/terminal/commands/"
    response = await send_api_request(
        method="GET",
        url=url,
        params=params.dict(exclude_none=True)
    )
    return {"code": 0, "message": "success", "data": response}


# 14.3 接口3：获取登录日志（文档14.3节）
class ListLoginLogsParams(BaseModel):
    """查询登录日志参数（文档14.3节Query Parameters）"""
    limit: PositiveInt = Field(default=20, le=100, description="每页条数（最大100）")
    offset: int = Field(default=0, ge=0, description="分页偏移量（从0开始）")
    search: Optional[str] = Field(None, description="搜索词（匹配用户名/IP）")
    date_from: str = Field(..., description="开始时间（必选，格式：2024-10-01T00:00:00Z）")
    date_to: str = Field(..., description="结束时间（必选，格式：2024-10-01T23:59:59Z）")

    # 自定义校验：时间格式
    @field_validator("date_from", "date_to")
    def date_format_check(cls, v):
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"时间格式错误：{v}，需符合ISO格式（如2024-10-01T00:00:00Z）")
        return v


@mcp.tool()
@validate_params(ListLoginLogsParams)
async def list_login_logs(params: ListLoginLogsParams) -> dict:
    """
    功能说明：查询用户登录日志（如Web/SSH登录记录，文档14.3节“获取登录日志”）
    接口路径：GET /api/v1/audits/login-logs/（文档14.3节API地址）
    参数说明：
      - limit/offset: 分页参数（必选）
      - search: 搜索词（可选，匹配用户名或IP）
      - date_from/date_to: 时间范围（必选，ISO格式）
    参数要求：
      - date_from不能晚于date_to
      - limit不能超过100
    返回值含义：
      {
        "code": 0（成功）/-32602（参数错误）,
        "message": "success",
        "data": {
          "count": 80（总登录次数）,
          "next": null,
          "previous": null,
          "results": [
            {
              "id": "uuid"（日志ID）,
              "username": "admin(admin)",
              "type": {"value": "W", "label": "Web"},  # 登录类型：Web/SSH等
              "ip": "10.1.240.254",  # 登录IP
              "city": "局域网",  # IP所属城市
              "user_agent": "Mozilla/5.0 ...",  # 浏览器/客户端信息
              "mfa": {"value": 0, "label": "禁用"},  # MFA状态
              "status": {"value": true, "label": "成功"},  # 登录状态
              "datetime": "2024/10/01 09:00:00 +0800"  # 登录时间
            }
          ]
        }
      }
    ID获取方式：无（登录日志无需ID关联其他接口，仅查询用）
    """
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/audits/login-logs/"
    response = await send_api_request(
        method="GET",
        url=url,
        params=params.dict(exclude_none=True)
    )
    return {"code": 0, "message": "success", "data": response}

class CreateJobParams(BaseModel):
    """创建任务参数"""
    assets: List[str] = Field(..., description="资产ID列表")
    args: str = Field(..., description="命令参数")


#@mcp.tool()
@validate_params(CreateJobParams)
async def create_job(params: CreateJobParams) -> dict:
    """
    功能说明：创建并执行任务
    接口路径：POST /api/v1/ops/jobs/
    参数说明：
      - assets: 资产ID列表（必填）
      - args: 命令参数（必填）
    固定参数：
      - module: "shell"（固定值）
      - runas: "root"（固定值）
      - runas_policy: "skip"（固定值）
      - instant: True（固定值）
      - is_periodic: False（固定值）
      - timeout: -1（固定值）
    返回值含义：
      {"code": 0, "message": "success", "data": 任务执行结果}
    """
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/ops/jobs/"
    payload = {
        "assets": params.assets,
        "nodes": [],
        "args": params.args,
        "module": "shell",
        "runas": "root",
        "runas_policy": "skip",
        "instant": True,
        "is_periodic": False,
        "timeout": -1
    }
    response = await send_api_request("POST", url, json=payload)
    return {"code": 0, "message": "success", "data": response}


@mcp.resource("resource://{task_id}/status")
async def get_job_execution_status(task_id: str) -> dict:
    """
    功能说明：查询任务执行状态
    接口路径：GET /api/v1/ops/job-execution/task-detail/{task_id}/
    参数说明：
      - task_id: 任务执行ID
    返回值含义：
      {
      "status": "success",
      "is_finished": true|false,
      "is_success": true|false,
      "time_cost": xxx,
      "job_id": "xxx",
      "summary": {
          "ok": [
              "10.1.13.141"
          ],
          "dark": {},
          "skipped": [],
          "failures": {}
      }
    }
    """
    url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/ops/job-execution/task-detail/{task_id}/"
    response = await send_api_request("GET", url)
    return {"code": 0, "message": "success", "data": response}




@mcp.resource("resource://{task_id}/log")
async def get_job_execution_log(task_id: str) -> str:
    """
    功能说明：查询任务执行日志文件
    日志路径：/data/jumpserver/core/data/celery/x/y/task-id.log
    其中 x 和 y 分别是 task-id 的第一个字符和第二个字符
    参数说明：
      - task_id: 任务执行ID（UUID格式）
    返回值：日志文件内容
    """
    # 构建日志文件路径
    first_char = task_id[0]
    second_char = task_id[1]
    #log_path = f"/data/jumpserver/core/data/celery/{first_char}/{second_char}/{task_id}.log"
    log_path = f"./{first_char}/{second_char}/{task_id}.log"
    
    try:
        # 读取日志文件内容
        with open(log_path, 'r', encoding='utf-8') as f:
            log_content = f.read()
        return log_content
    except FileNotFoundError:
        raise FileNotFoundError(f"任务执行日志文件不存在: {log_path}")
    except Exception as e:
        raise Exception(f"读取日志文件失败: {str(e)}")




# SUBSCRIBERS = set()

# async def broadcast_event(event: dict):
#     for q in list(SUBSCRIBERS):
#         try:
#             q.put_nowait(event)
#         except asyncio.QueueFull:
#             pass

# @mcp.stream("task.events")
# async def stream_task_events():
#     queue = asyncio.Queue()
#     SUBSCRIBERS.add(queue)
#     try:
#         while True:
#             event = await queue.get()
#             yield event
#     finally:
#         SUBSCRIBERS.remove(queue)


# async def poll_job_status(task_id: str):
#     while True:
#         resp = await send_api_request("GET", f"{CONFIG['JUMPSERVER_API_BASE_URL']}/ops/job-execution/task-detail/{task_id}/")
#         await broadcast_event({
#             "task_id": task_id,
#             "event": "status_update",
#             "status": resp["status"],
#             "is_finished": resp["is_finished"]
#         })
#         if resp["is_finished"]:
#             break
#         await asyncio.sleep(2)


class ExecuteJobWithPollingParams(BaseModel):
    """执行任务并轮询状态参数"""
    assets: List[str] = Field(..., description="资产ID列表")
    args: str = Field(..., description="命令参数")


@mcp.tool()
@validate_params(ExecuteJobWithPollingParams)
async def execute_job_with_polling(params: ExecuteJobWithPollingParams) -> dict:
    """
    功能说明：创建任务并每隔2秒查询状态，直到任务完成，然后返回日志内容
    执行流程：
      1. 创建任务
      2. 每隔2秒查询任务状态
      3. 任务完成后读取日志
      4. 返回完整执行结果
    参数说明：
      - assets: 资产ID列表（必填）
      - args: 命令参数（必填）
    返回值：
      {
        "code": 0,
        "message": "任务执行完成",
        "data": {
          "task_id": "任务ID",
          "status": "completed",
          "log": "完整的执行日志",
          "execution_time": "执行耗时",
          "poll_count": "轮询次数"
        }
      }
    """
    import time
    start_time = time.time()
    poll_count = 0
    
    # 1. 创建任务
    create_params = CreateJobParams(
        assets=params.assets,
        args=params.args
    )
    create_result = await create_job(create_params)
    
    if create_result.get("code") != 0:
        return create_result
    
    task_id = create_result["data"].get("id") or create_result["data"].get("task_id")
    print(f"task_id={task_id}")
    if not task_id:
        return {"code": 1, "message": "创建任务失败：未获取到任务ID", "data": None}
    
    # 2. 轮询任务状态直到完成
    max_attempts = 300  # 最大轮询次数（约10分钟）
    
    for attempt in range(max_attempts):
        poll_count += 1
        
        # 查询任务状态
        status_url = f"{CONFIG['JUMPSERVER_API_BASE_URL']}/ops/job-execution/task-detail/{task_id}/"
        status_response = await send_api_request("GET", status_url)
        
        is_finished = status_response.get("is_finished", False)
        is_success = status_response.get("is_success", False)
        current_status = status_response.get("status", "unknown")
        
        print(f"轮询 {poll_count}: 状态={current_status}, 完成={is_finished}, 成功={is_success}")
        
        if is_finished:
            # 3. 任务完成，读取日志
            try:
                # 构建日志文件路径
                first_char = task_id[0]
                second_char = task_id[1]
                log_path = os.path.join(CONFIG["TASK_LOG_DIR"], first_char,second_char,f"{task_id}.log")
                
                # 读取日志文件内容
                with open(log_path, 'r', encoding='utf-8') as f:
                    log_content = f.read()
                
                execution_time = time.time() - start_time
                
                return {
                    "code": 0,
                    "message": "任务执行完成",
                    "data": {
                        "task_id": task_id,
                        "status": "success" if is_success else "failed",
                        "log": log_content,
                        "execution_time": f"{execution_time:.2f}秒",
                        "poll_count": poll_count,
                        "final_status": status_response
                    }
                }
            except FileNotFoundError:
                execution_time = time.time() - start_time
                return {
                    "code": 1,
                    "message": "任务完成但日志文件不存在",
                    "data": {
                        "task_id": task_id,
                        "status": "success" if is_success else "failed",
                        "log": "日志文件未找到",
                        "execution_time": f"{execution_time:.2f}秒",
                        "poll_count": poll_count,
                        "final_status": status_response
                    }
                }
            except Exception as e:
                execution_time = time.time() - start_time
                return {
                    "code": 1,
                    "message": f"读取日志失败: {str(e)}",
                    "data": {
                        "task_id": task_id,
                        "status": "success" if is_success else "failed",
                        "log": f"日志读取错误: {str(e)}",
                        "execution_time": f"{execution_time:.2f}秒",
                        "poll_count": poll_count,
                        "final_status": status_response
                    }
                }
        
        # 任务未完成，等待2秒后继续轮询
        await asyncio.sleep(2)
    
    # 超时处理
    execution_time = time.time() - start_time
    return {
        "code": 1,
        "message": f"任务执行超时（{max_attempts * 2}秒）",
        "data": {
            "task_id": task_id,
            "status": "timeout",
            "log": "任务执行超时，请稍后手动查询状态",
            "execution_time": f"{execution_time:.2f}秒",
            "poll_count": poll_count
        }
    }


async def main():
    # 使用HTTP传输方式启动服务器
     await mcp.run_streamable_http_async(
        host="0.0.0.0",
        port=9000,
        path="/mcp" 
    )
# ====== 12. 服务启动======
if __name__ == "__main__":
    logger.info("JumpServer MCP Server 启动中...")
    logger.info(f"API地址：{CONFIG['JUMPSERVER_API_BASE_URL']}，默认组织ID：{CONFIG['DEFAULT_ORG_ID']}")
    
    # mcp.run(
    #     transport="streamable-http",
    #     host="0.0.0.0",
    #     port=9000,
    #     path="/mcp"
    # )
    asyncio.run(main())
  
    
