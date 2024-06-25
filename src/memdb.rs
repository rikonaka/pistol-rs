use anyhow::Result;
use rusqlite::params;
use rusqlite::Connection;

use crate::layers::system_neighbour_cache;
use crate::layers::system_neighbour_cache6;
use crate::layers::system_route;
use crate::layers::system_route6;

#[derive(Debug)]
pub struct NeighborCache {
    // pub id: i32,
    // pub ipaddr: String,
    pub macaddr: Option<String>,
}

#[derive(Debug)]
pub struct RouteCache {
    // pub id: i32,
    // pub name: String,
    pub ipaddr: String,
    pub macaddr: Option<String>,
}

// Save necessary data in memory for later use.
// Avoid running system commands every time you use it.
pub struct MemDB {
    conn: Connection,
    neighbor_cache_table_name: String,
    route_cache_table_name: String,
}

impl MemDB {
    pub fn init() -> Result<MemDB> {
        let conn = Connection::open_in_memory()?;
        let neighbor_cache_table_name = String::from("neighbor_cache");
        let route_cache_table_name = String::from("route_cache");
        let sql = format!(
            "CREATE TABLE IF NOT EXISTS {} (
            id INTEGER PRIMARY KEY,
            ipaddr TEXT NOT NULL UNIQUE,
            macaddr TEXT)",
            neighbor_cache_table_name
        );
        conn.execute(&sql, ())?;

        let sql = format!(
            "CREATE TABLE IF NOT EXISTS {} (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            ipaddr TEXT,
            macaddr TEXT)",
            route_cache_table_name
        );
        conn.execute(&sql, ())?;

        Ok(MemDB {
            conn,
            neighbor_cache_table_name,
            route_cache_table_name,
        })
    }
    pub fn fill_system_info(&self) -> Result<()> {
        let snc = system_neighbour_cache()?;
        match snc {
            Some(snc) => {
                for (ipaddr, macaddr) in snc {
                    match self.neighbor_insert(ipaddr.to_string(), Some(macaddr.to_string())) {
                        _ => (),
                    };
                }
            }
            None => (),
        }

        let snc6 = system_neighbour_cache6()?;
        match snc6 {
            Some(snc6) => {
                for (ipaddr, macaddr) in snc6 {
                    match self.neighbor_insert(ipaddr.to_string(), Some(macaddr.to_string())) {
                        _ => (),
                    }
                }
            }
            None => (),
        }

        let route_ipaddr = system_route()?;
        // Search in the cache, so isroute is false here.
        match route_ipaddr {
            Some(route_ipaddr) => match self.search_mac(route_ipaddr.to_string())? {
                Some(nc) => match self.route_insert(route_ipaddr.to_string(), nc.macaddr) {
                    _ => (),
                },
                None => match self.route_insert(route_ipaddr.to_string(), None) {
                    _ => (),
                },
            },
            None => (),
        }

        let route_ipaddr6 = system_route6()?;
        match route_ipaddr6 {
            Some(route_ipaddr6) => match self.search_mac(route_ipaddr6.to_string())? {
                Some(nc) => match self.route_insert6(route_ipaddr6.to_string(), nc.macaddr) {
                    _ => (),
                },
                None => match self.route_insert6(route_ipaddr6.to_string(), None) {
                    _ => (),
                },
            },
            None => (),
        }

        Ok(())
    }
    pub fn neighbor_insert(&self, ipaddr: String, macaddr: Option<String>) -> Result<usize> {
        let sql = format!(
            "INSERT INTO {} (ipaddr, macaddr) VALUES (?1, ?2)",
            self.neighbor_cache_table_name
        );
        let effected_rows = self.conn.execute(&sql, (ipaddr, macaddr))?;
        Ok(effected_rows)
    }
    pub fn route_insert(&self, ipaddr: String, macaddr: Option<String>) -> Result<usize> {
        let sql = format!(
            "INSERT INTO {} (name, ipaddr, macaddr) VALUES (?1, ?2, ?3)",
            self.route_cache_table_name
        );
        let effected_rows = self.conn.execute(&sql, ("route_ipv4", ipaddr, macaddr))?;
        Ok(effected_rows)
    }
    pub fn route_insert6(&self, ipaddr: String, macaddr: Option<String>) -> Result<usize> {
        let sql = format!(
            "INSERT INTO {} (name, ipaddr, macaddr) VALUES (?1, ?2, ?3)",
            self.route_cache_table_name
        );
        let effected_rows = self.conn.execute(&sql, ("route_ipv6", ipaddr, macaddr))?;
        Ok(effected_rows)
    }
    pub fn update_route(&self, ipaddr: String, macaddr: Option<String>) -> Result<usize> {
        match self.neighbor_insert(ipaddr.clone(), macaddr.clone()) {
            Ok(_) => Ok(0),
            Err(_) => {
                // If the value already in database, the UNIQUE constrain will raise error here.
                let sql = format!(
                    "UPDATE {} SET macaddr = ?1 WHERE name = {} AND ipaddr = ?2",
                    self.route_cache_table_name, "route_ipv4",
                );
                let effected_rows = self.conn.execute(&sql, (macaddr, ipaddr))?;
                Ok(effected_rows)
            }
        }
    }
    pub fn update_route6(&self, ipaddr: String, macaddr: Option<String>) -> Result<usize> {
        match self.neighbor_insert(ipaddr.clone(), macaddr.clone()) {
            Ok(_) => Ok(0),
            Err(_) => {
                // If the value already in database, the UNIQUE constrain will raise error here.
                let sql = format!(
                    "UPDATE {} SET macaddr = ?1 WHERE name = {} AND ipaddr = ?2",
                    self.route_cache_table_name, "route_ipv6",
                );
                let effected_rows = self.conn.execute(&sql, (macaddr, ipaddr))?;
                Ok(effected_rows)
            }
        }
    }
    pub fn search_mac(&self, ipaddr: String) -> Result<Option<NeighborCache>> {
        let sql = format!(
            "SELECT * FROM {} WHERE ipaddr = ?1 LIMIT 1",
            self.neighbor_cache_table_name
        );
        let mut sql = self.conn.prepare(&sql)?;
        let neighbor_cache_iter = sql.query_map(params![ipaddr], |row| {
            Ok(NeighborCache {
                // id: row.get(0)?,
                // ipaddr: row.get(1)?,
                macaddr: row.get(2)?,
            })
        })?;

        for nc in neighbor_cache_iter {
            match nc {
                Ok(nc) => return Ok(Some(nc)),
                Err(_) => return Ok(None),
            }
        }
        Ok(None)
    }
    pub fn search_route_ip(&self) -> Result<Option<RouteCache>> {
        let sql = format!(
            "SELECT * FROM {} WHERE name = ?1 LIMIT 1",
            self.route_cache_table_name
        );
        let mut sql = self.conn.prepare(&sql)?;
        let name = "route_ipv4";
        let route_cache_iter = sql.query_map(params![name], |row| {
            Ok(RouteCache {
                // id: row.get(0)?,
                // name: row.get(1)?,
                ipaddr: row.get(2)?,
                macaddr: row.get(3)?,
            })
        })?;

        for rc in route_cache_iter {
            match rc {
                Ok(rc) => return Ok(Some(rc)),
                Err(_) => return Ok(None),
            }
        }
        Ok(None)
    }
    pub fn search_route_ip6(&self) -> Result<Option<RouteCache>> {
        let sql = format!(
            "SELECT * FROM {} WHERE name = ?1 LIMIT 1",
            self.route_cache_table_name
        );
        let mut sql = self.conn.prepare(&sql)?;
        let name = "route_ipv6";
        let route_cache_iter = sql.query_map(params![name], |row| {
            Ok(RouteCache {
                // id: row.get(0)?,
                // name: row.get(1)?,
                ipaddr: row.get(2)?,
                macaddr: row.get(3)?,
            })
        })?;

        for rc in route_cache_iter {
            match rc {
                Ok(rc) => return Ok(Some(rc)),
                Err(_) => return Ok(None),
            }
        }
        Ok(None)
    }
    // for debug use
    fn _debug_select_all(&self) -> Result<Vec<NeighborCache>> {
        let sql = format!("SELECT * FROM {}", self.neighbor_cache_table_name);
        let mut sql = self.conn.prepare(&sql)?;
        let neighbor_cache_iter = sql.query_map(params![], |row| {
            Ok(NeighborCache {
                // id: row.get(0)?,
                // ipaddr: row.get(1)?,
                macaddr: row.get(2)?,
            })
        })?;

        let mut ret = vec![];
        for nc in neighbor_cache_iter {
            match nc {
                Ok(nc) => ret.push(nc),
                Err(_) => (),
            }
        }
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_memdb() -> Result<()> {
        let memdb = MemDB::init()?;
        memdb.fill_system_info()?;

        let alls = memdb._debug_select_all()?;
        for a in alls {
            println!("{:?}", a)
        }

        println!(">>>>>>>>>>>>>>>> ");

        memdb.neighbor_insert(
            "192.168.1.1".to_string(),
            Some("00:0c:29:43:9c:82".to_string()),
        )?;
        let ret = memdb.search_route_ip()?;
        match ret {
            Some(ret) => println!("{:?}", ret),
            None => println!("null value found"),
        }

        Ok(())
    }
}
