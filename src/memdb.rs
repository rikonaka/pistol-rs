use anyhow::Result;
use rusqlite::params;
use rusqlite::Connection;

use crate::layers::system_neighbour_cache;
use crate::layers::system_neighbour_cache6;
use crate::layers::system_route;
use crate::layers::system_route6;

#[derive(Debug)]
pub struct NeighborCache {
    pub id: i32,
    pub ipaddr: String,
    pub macaddr: Option<String>,
    pub isroute: bool,
    pub isipv6: bool,
}

// Save necessary data in memory for later use.
// Avoid running system commands every time you use it.
pub struct MemDB {
    conn: Connection,
    table_name: String,
}

impl MemDB {
    pub fn init() -> Result<MemDB> {
        let conn = Connection::open_in_memory()?;
        let table_name = String::from("neighbor_cache");
        let sql = format!(
            "CREATE TABLE IF NOT EXISTS {} (
            id INTEGER PRIMARY KEY,
            ipaddr TEXT NOT NULL UNIQUE,
            macaddr TEXT,
            isroute INTEGER,
            isipv6 INTEGER)",
            table_name
        );
        conn.execute(&sql, ())?;
        Ok(MemDB { conn, table_name })
    }
    pub fn fill_system_info(&self) -> Result<()> {
        let snc = system_neighbour_cache()?;
        match snc {
            Some(snc) => {
                for (ipaddr, macaddr) in snc {
                    match self.insert(ipaddr.to_string(), Some(macaddr.to_string()), false, false) {
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
                    match self.insert(ipaddr.to_string(), Some(macaddr.to_string()), false, true) {
                        _ => (),
                    }
                }
            }
            None => (),
        }

        let route_ipaddr = system_route()?;
        // Search in the cache, so isroute is false here.
        match route_ipaddr {
            Some(route_ipaddr) => {
                match self.search_macaddr(route_ipaddr.to_string(), false, false)? {
                    Some(nc) => {
                        match self.insert(route_ipaddr.to_string(), nc.macaddr, true, false) {
                            _ => (),
                        }
                    }
                    None => match self.insert(route_ipaddr.to_string(), None, true, false) {
                        _ => (),
                    },
                }
            }
            None => (),
        }

        let route_ipaddr6 = system_route6()?;
        match route_ipaddr6 {
            Some(route_ipaddr6) => {
                match self.search_macaddr(route_ipaddr6.to_string(), false, true)? {
                    Some(nc) => {
                        match self.insert(route_ipaddr6.to_string(), nc.macaddr, true, true) {
                            _ => (),
                        }
                    }
                    None => match self.insert(route_ipaddr6.to_string(), None, true, true) {
                        _ => (),
                    },
                }
            }
            None => (),
        }

        Ok(())
    }
    pub fn insert(
        &self,
        ipaddr: String,
        macaddr: Option<String>,
        isroute: bool,
        isipv6: bool,
    ) -> Result<usize> {
        let sql = format!(
            "INSERT INTO {} (ipaddr, macaddr, isroute, isipv6) VALUES (?1, ?2, ?3, ?4)",
            self.table_name
        );
        let effected_rows = self
            .conn
            .execute(&sql, (ipaddr, macaddr, isroute, isipv6))?;
        Ok(effected_rows)
    }
    pub fn update_route(
        &self,
        ipaddr: String,
        macaddr: Option<String>,
        isipv6: bool,
    ) -> Result<usize> {
        match self.insert(ipaddr.clone(), macaddr.clone(), true, isipv6) {
            Ok(_) => Ok(0),
            Err(_) => {
                // If the value already in database, the UNIQUE constrain will raise error here.
                let sql = format!(
                    "UPDATE {} SET isroute = true, macaddr = ?1 WHERE ipaddr = ?2",
                    self.table_name
                );
                let effected_rows = self.conn.execute(&sql, (macaddr, ipaddr))?;
                Ok(effected_rows)
            }
        }
    }
    pub fn search_macaddr(
        &self,
        ipaddr: String,
        isroute: bool,
        isipv6: bool,
    ) -> Result<Option<NeighborCache>> {
        let sql = format!(
            "SELECT * FROM {} WHERE ipaddr = ?1 AND isroute = ?2 AND isipv6 = ?3 LIMIT 1",
            self.table_name
        );
        let mut sql = self.conn.prepare(&sql)?;
        let neighbor_cache_iter = sql.query_map(params![ipaddr, isroute, isipv6], |row| {
            Ok(NeighborCache {
                id: row.get(0)?,
                ipaddr: row.get(1)?,
                macaddr: row.get(2)?,
                isroute: row.get(3)?,
                isipv6: row.get(4)?,
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
    pub fn search_route_ipaddr(&self, isipv6: bool) -> Result<Option<NeighborCache>> {
        let sql = format!(
            "SELECT * FROM {} WHERE isroute = ?1 AND isipv6 = ?2 LIMIT 1",
            self.table_name
        );
        let mut sql = self.conn.prepare(&sql)?;
        let isroute = true;
        let neighbor_cache_iter = sql.query_map(params![isroute, isipv6], |row| {
            Ok(NeighborCache {
                id: row.get(0)?,
                ipaddr: row.get(1)?,
                macaddr: row.get(2)?,
                isroute: row.get(3)?,
                isipv6: row.get(4)?,
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
    // for debug use
    fn _debug_select_all(&self) -> Result<Vec<NeighborCache>> {
        let sql = format!("SELECT * FROM {}", self.table_name);
        let mut sql = self.conn.prepare(&sql)?;
        let neighbor_cache_iter = sql.query_map(params![], |row| {
            Ok(NeighborCache {
                id: row.get(0)?,
                ipaddr: row.get(1)?,
                macaddr: row.get(2)?,
                isroute: row.get(3)?,
                isipv6: row.get(4)?,
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

        memdb.insert(
            "192.168.1.1".to_string(),
            Some("00:0c:29:43:9c:82".to_string()),
            true,
            false,
        )?;
        let ret = memdb.search_route_ipaddr(false)?;
        match ret {
            Some(ret) => println!("{:?}", ret),
            None => println!("null value found"),
        }

        Ok(())
    }
}
