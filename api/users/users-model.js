const db = require('../../data/dbConfig');

function find() {
  return db("users")
}

function findBy(filter) {
  return db("users")
    .where(filter)
}

function findById(user_id) {
  return db("users as u")
    .where("u.id", user_id)
    .first()
}

async function add(user) {
    const [id] = await db('users').insert(user)
    return findById(id)
}

module.exports = {
  add,
  find,
  findBy,
  findById,
};