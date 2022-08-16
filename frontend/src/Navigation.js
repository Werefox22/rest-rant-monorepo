import { useState, useEffect, useContext } from 'react'
import { useHistory } from "react-router";
import { CurrentUser } from './contexts/CurrentUser';

function Navigation() {

    const history = useHistory()

    const { currentUser, setCurrentUser } = useContext(CurrentUser)

    let loginActions = (
        <>
            <li style={{ float: 'right' }}>
                <a href="#" onClick={() => history.push("/sign-up")}>
                    Sign Up
                </a>
            </li>
            <li style={{ float: 'right' }}>
                <a href="#" onClick={() => history.push("/login")}>
                    Login
                </a>
            </li>
        </>
    )

    if (currentUser) {
        loginActions = (
            <>
                <li style={{float: 'right'}}>
                    <a href='#' onClick={() => {
                        setCurrentUser(null)
                        localStorage.removeItem('token')
                        history.push(`/`)
                    }}>
                        Log Out
                    </a>
                </li>
                <li style={{ float: 'right' }}>
                    Logged in as {currentUser.firstName} {currentUser.lastName}
                </li>
            </>
        )
    }

    // only display the Add Place button if the user is an admin
    let addPlaceButton = null
    if (currentUser?.role === 'admin') {
        addPlaceButton = (
            <li>
                <a href="#" onClick={() => history.push("/places/new")}>
                    Add Place
                </a>
            </li>
        )
    }

    return (
        <nav>
            <ul>
                <li>
                    <a href="#" onClick={() => history.push("/")}>
                        Home
                    </a>
                </li>
                <li>
                    <a href="#" onClick={() => history.push("/places")}>
                        Places
                    </a>
                </li>
                {loginActions}
                {addPlaceButton}
            </ul>
        </nav>
    )
}

export default Navigation;