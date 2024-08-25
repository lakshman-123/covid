const express = require('express')
const path = require('path')
const sqlite3 = require('sqlite3')
const {open} = require('sqlite')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const app = express()

app.use(express.json())

const databasePath = path.join(__dirname, 'covid19IndiaPortal.db')
let database = null
const JWT_SECRET = 'vivek_secret_key' // Use a strong secret key

const initializeDbAndServer = async () => {
  try {
    database = await open({filename: databasePath, driver: sqlite3.Database})
    app.listen(3000, () => {
      console.log('Server is running on http://localhost:3000')
    })
  } catch (error) {
    console.error(`Database error: ${error}`)
    process.exit(1)
  }
}

initializeDbAndServer()

// API 1: User Login
app.post('/login/', async (req, res) => {
  const {username, password} = req.body
  const userDetailsQuery = `SELECT * FROM user WHERE username = ?`
  try {
    const userDetails = await database.get(userDetailsQuery, [username])
    if (userDetails) {
      const isPasswordValid = await bcrypt.compare(
        password,
        userDetails.password,
      )
      if (isPasswordValid) {
        const payload = {username: userDetails.username}
        const jwtToken = jwt.sign(payload, JWT_SECRET, {expiresIn: '1h'})
        res.send({jwtToken}) // Scenario 3
      } else {
        res.status(400).send('Invalid password') // Scenario 2
      }
    } else {
      res.status(400).send('Invalid user') // Scenario 1
    }
  } catch (error) {
    res.status(500).send('Internal Server Error')
  }
})

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization
  const jwtToken = authHeader && authHeader.split(' ')[1]
  if (jwtToken) {
    jwt.verify(jwtToken, JWT_SECRET, (err, user) => {
      if (err) return res.status(401).send('Invalid JWT Token')
      req.user = user
      next() // Proceed to next middleware or route handler
    })
  } else {
    res.status(401).send('Invalid JWT Token')
  }
}

// API 2: Get All States
app.get('/states/', authenticateToken, async (req, res) => {
  try {
    const getStatesQuery = 'SELECT * FROM state'
    const states = await database.all(getStatesQuery)
    const formattedStates = states.map(
      ({state_id, state_name, population}) => ({
        stateId: state_id,
        stateName: state_name,
        population,
      }),
    )
    res.send(formattedStates)
  } catch (error) {
    res.status(500).send('Internal Server Error')
  }
})

// API 3: Get State by ID
app.get('/states/:stateId/', authenticateToken, async (req, res) => {
  const {stateId} = req.params
  try {
    const getStateDetailsQuery = 'SELECT * FROM state WHERE state_id = ?'
    const state = await database.get(getStateDetailsQuery, [stateId])
    if (state) {
      res.send({
        stateId: state.state_id,
        stateName: state.state_name,
        population: state.population,
      })
    } else {
      res.status(404).send('State not found')
    }
  } catch (error) {
    res.status(500).send('Internal Server Error')
  }
})

// API 4: Create District
app.post('/districts/', authenticateToken, async (req, res) => {
  const {districtName, stateId, cases, cured, active, deaths} = req.body
  try {
    const createDistrictQuery = `INSERT INTO district (district_name, state_id, cases, cured, active, deaths) VALUES (?, ?, ?, ?, ?, ?)`
    await database.run(createDistrictQuery, [
      districtName,
      stateId,
      cases,
      cured,
      active,
      deaths,
    ])
    res.send('District Successfully Added')
  } catch (error) {
    res.status(500).send('Internal Server Error')
  }
})

// API 5: Get District by ID
app.get('/districts/:districtId/', authenticateToken, async (req, res) => {
  const {districtId} = req.params
  try {
    const getDistrictQuery = 'SELECT * FROM district WHERE district_id = ?'
    const district = await database.get(getDistrictQuery, [districtId])
    if (district) {
      res.send({
        districtId: district.district_id,
        districtName: district.district_name,
        stateId: district.state_id,
        cases: district.cases,
        cured: district.cured,
        active: district.active,
        deaths: district.deaths,
      })
    } else {
      res.status(404).send('District not found')
    }
  } catch (error) {
    res.status(500).send('Internal Server Error')
  }
})

// API 6: Delete District
app.delete('/districts/:districtId/', authenticateToken, async (req, res) => {
  const {districtId} = req.params
  try {
    const deleteDistrictQuery = 'DELETE FROM district WHERE district_id = ?'
    const result = await database.run(deleteDistrictQuery, [districtId])
    if (result.changes) {
      res.send('District Removed')
    } else {
      res.status(404).send('District not found')
    }
  } catch (error) {
    res.status(500).send('Internal Server Error')
  }
})

// API 7: Update District
app.put('/districts/:districtId/', authenticateToken, async (req, res) => {
  const {districtId} = req.params
  const {districtName, stateId, cases, cured, active, deaths} = req.body
  try {
    const updateDistrictQuery = `UPDATE district SET
      district_name = ?,
      state_id = ?,
      cases = ?,
      cured = ?,
      active = ?,
      deaths = ?
      WHERE district_id = ?`
    const result = await database.run(updateDistrictQuery, [
      districtName,
      stateId,
      cases,
      cured,
      active,
      deaths,
      districtId,
    ])
    if (result.changes) {
      res.send('District Details Updated')
    } else {
      res.status(404).send('District not found')
    }
  } catch (error) {
    res.status(500).send('Internal Server Error')
  }
})

// API 8: Get State Statistics
app.get('/states/:stateId/stats/', authenticateToken, async (req, res) => {
  const {stateId} = req.params
  try {
    const getStatsQuery = `SELECT 
      SUM(cases) AS totalCases, 
      SUM(cured) AS totalCured, 
      SUM(active) AS totalActive, 
      SUM(deaths) AS totalDeaths 
      FROM district WHERE state_id = ?`
    const stats = await database.get(getStatsQuery, [stateId])
    res.send(stats)
  } catch (error) {
    res.status(500).send('Internal Server Error')
  }
})

module.exports = app
